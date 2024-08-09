#![warn(clippy::unwrap_used)]

use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct Client {
    client: reqwest::blocking::Client,
    key_file: String,
    secret_api_key: String,
    api_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("porkbun API returned an error: \"{message}\"")]
    Api { message: String },
    #[error("porkbun API returned an unrecognized response ({response}): {error}")]
    MalformedApi {
        error: serde_json::Error,
        response: String,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Status {
    #[serde(rename = "SUCCESS")]
    Success,
    #[serde(rename = "ERROR")]
    Error,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum RecordType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "MX")]
    Mx,
    #[serde(rename = "CNAME")]
    Cname,
    #[serde(rename = "ALIAS")]
    Alias,
    #[serde(rename = "TXT")]
    Txt,
    #[serde(rename = "NS")]
    Ns,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "SRV")]
    Srv,
    #[serde(rename = "TLSA")]
    Tlsa,
    #[serde(rename = "CAA")]
    Caa,
    #[serde(rename = "HTTPS")]
    Https,
    #[serde(rename = "SVCB")]
    Svcb,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: RecordType,
    pub content: String,
    pub ttl: String,
    pub prio: String,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Ipv4Record {
    pub id: String,
    pub name: String,
    #[serde(rename = "content")]
    pub address: Ipv4Addr,
    pub ttl: String,
    pub prio: String,
    pub notes: Option<String>,
}

/// Authentication
impl Client {
    /// Open a porkbun api key file.
    ///
    /// This is a JSON file formatted the way that the porkbun ping api expects.
    /// For example:
    /// ```json
    /// {
    ///     "secretapikey": "YOUR_SECRET_API_KEY",
    ///     "apikey": "YOUR_API_KEY",
    /// }
    /// ```
    pub fn open_keys(path: impl AsRef<std::path::Path>) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct Keys {
            #[serde(rename = "apikey")]
            api: String,
            #[serde(rename = "secretapikey")]
            secret_api: String,
        }

        let key_file = std::fs::read_to_string(path)?;
        let keys: Keys = serde_json::from_str(&key_file)?;

        Ok(Self {
            client: reqwest::blocking::Client::new(),
            api_key: keys.api,
            secret_api_key: keys.secret_api,
            key_file,
        })
    }

    /// Tests authentication and returns the ipv4 address used to make the request.
    ///
    /// api-ipv4.porkbun.com forces the use of ipv4, which is useful for updating the A record.
    pub fn ping_ipv4(&self) -> Result<Option<Ipv4Addr>> {
        const URL: &str = "https://api-ipv4.porkbun.com/api/json/v3/ping";

        #[derive(Clone, Debug, serde::Deserialize)]
        struct PingResponse {
            status: Status,
            #[serde(default)]
            message: String,
            #[serde(rename = "yourIp")]
            ip: Option<Ipv4Addr>,
        }

        #[cfg(feature = "tracing")]
        tracing::info!("POST {URL}");
        let response = self
            .client
            .post(URL)
            .body(self.key_file.clone())
            .send()?
            .text()?;
        #[cfg(feature = "tracing")]
        tracing::info!("response: {response}");
        let response: PingResponse = serde_json::from_str(&response)
            .map_err(|error| Error::MalformedApi { error, response })?;
        #[cfg(feature = "tracing_debug")]
        tracing::debug!("parsed response: {response:?}");
        match response.status {
            Status::Success => Ok(response.ip),
            Status::Error => Err(Error::Api {
                message: response.message,
            }),
        }
    }
}

/// Fetch records
impl Client {
    /// Fetches all DNS records for a given domain.
    ///
    /// These can be of any type and with any name.
    /// Consider using a more specific method if you're only interested in certain records,
    /// such as:
    /// - [Client::fetch_ipv4_records]
    /// - [Client::fetch_ipv4_address_by_name]
    pub fn fetch_records(&self, domain: &str) -> Result<Vec<DnsRecord>> {
        #[derive(Clone, Debug, serde::Deserialize)]
        struct FetchRecordsResponse {
            status: Status,
            #[serde(default)]
            message: String,
            #[serde(default)]
            records: Vec<DnsRecord>,
        }

        let url = format!("https://api.porkbun.com/api/json/v3/dns/retrieve/{domain}");

        #[cfg(feature = "tracing")]
        tracing::info!("POST {url}");
        let response = self
            .client
            .post(&url)
            .body(self.key_file.clone())
            .send()?
            .text()?;
        #[cfg(feature = "tracing")]
        tracing::info!("response: {response}");
        let response: FetchRecordsResponse = serde_json::from_str(&response)
            .map_err(|error| Error::MalformedApi { error, response })?;
        #[cfg(feature = "tracing_debug")]
        tracing::debug!("parsed response: {response:?}");

        match response.status {
            Status::Success => Ok(response.records),
            Status::Error => Err(Error::Api {
                message: response.message,
            }),
        }
    }

    /// Fetches all DNS A records for a given domain.
    pub fn fetch_ipv4_records(
        &self,
        domain: &str,
        subdomain: Option<&str>,
    ) -> Result<Vec<Ipv4Record>> {
        let mut url =
            format!("https://api.porkbun.com/api/json/v3/dns/retrieveByNameType/{domain}/A/");
        if let Some(subdomain) = subdomain {
            url.push_str(subdomain);
        }

        #[derive(Clone, Debug, serde::Deserialize)]
        struct FetchIpv4RecordsResponse {
            status: Status,
            #[serde(default)]
            message: String,
            #[serde(default)]
            records: Vec<Ipv4Record>,
        }

        #[cfg(feature = "tracing")]
        tracing::info!("POST {url}");
        let response = self
            .client
            .post(&url)
            .body(self.key_file.clone())
            .send()?
            .text()?;
        #[cfg(feature = "tracing")]
        tracing::info!("response: {response}");
        let response: FetchIpv4RecordsResponse = serde_json::from_str(&response)
            .map_err(|error| Error::MalformedApi { error, response })?;
        #[cfg(feature = "tracing_debug")]
        tracing::debug!("parsed response: {response:?}");

        match response.status {
            Status::Success => Ok(response.records),
            Status::Error => Err(Error::Api {
                message: response.message,
            }),
        }
    }
}

/// Create records
impl Client {
    pub fn create_record(
        &self,
        domain: &str,
        name: Option<&str>,
        ty: RecordType,
        content: &str,
        ttl: Option<&str>,
        prio: Option<&str>,
    ) -> Result<Option<u32>> {
        #[derive(Clone, Debug, serde::Serialize)]
        struct Body<'a> {
            #[serde(rename = "secretapikey")]
            secret_api: &'a str,
            #[serde(rename = "apikey")]
            api: &'a str,
            pub name: Option<&'a str>,
            #[serde(rename = "type")]
            pub ty: RecordType,
            pub content: &'a str,
            pub ttl: Option<&'a str>,
            pub prio: Option<&'a str>,
        }

        #[derive(Clone, Debug, serde::Deserialize)]
        struct Response {
            status: Status,
            #[serde(default)]
            message: String,
            id: Option<u32>,
        }

        let url = format!("https://api.porkbun.com/api/json/v3/dns/create/{domain}");
        #[cfg(feature = "tracing")]
        tracing::info!("POST {url}");
        let response = self
            .client
            .post(&url)
            .body(serde_json::to_string(&Body {
                secret_api: &self.secret_api_key,
                api: &self.api_key,
                name,
                ty,
                content,
                ttl,
                prio,
            })?)
            .send()?
            .text()?;
        #[cfg(feature = "tracing")]
        tracing::info!("response: {response}");
        let response: Response = serde_json::from_str(&response)
            .map_err(|error| Error::MalformedApi { error, response })?;
        #[cfg(feature = "tracing_debug")]
        tracing::debug!("parsed response: {response:?}");
        match response.status {
            Status::Success => Ok(response.id),
            Status::Error => Err(Error::Api {
                message: response.message,
            }),
        }
    }
}

/// Edit records
impl Client {
    pub fn edit_ipv4_address(
        &self,
        domain: &str,
        subdomain: Option<&str>,
        address: &Ipv4Addr,
    ) -> Result<()> {
        #[derive(Clone, Debug, serde::Serialize)]
        struct EditDnsRecordBody<'a> {
            #[serde(rename = "secretapikey")]
            secret_api: &'a str,
            #[serde(rename = "apikey")]
            api: &'a str,
            #[serde(rename = "type")]
            ty: &'static str,
            content: &'a Ipv4Addr,
        }

        #[derive(Clone, Debug, serde::Deserialize)]
        struct EditDnsRecordResponse {
            status: Status,
            #[serde(default)]
            message: String,
        }

        let mut url = format!("https://api.porkbun.com/api/json/v3/dns/editByNameType/{domain}/A/");
        if let Some(subdomain) = subdomain {
            url.push_str(subdomain);
        }

        #[cfg(feature = "tracing")]
        tracing::info!("POST {url}");
        let response = self
            .client
            .post(&url)
            .body(serde_json::to_string(&EditDnsRecordBody {
                secret_api: &self.secret_api_key,
                api: &self.api_key,
                ty: "A",
                content: address,
            })?)
            .send()?
            .text()?;
        #[cfg(feature = "tracing")]
        tracing::info!("response: {response}");
        let response: EditDnsRecordResponse = serde_json::from_str(&response)
            .map_err(|error| Error::MalformedApi { error, response })?;
        #[cfg(feature = "tracing_debug")]
        tracing::debug!("parsed response: {response:?}");
        match response.status {
            Status::Success => Ok(()),
            Status::Error => Err(Error::Api {
                message: response.message,
            }),
        }
    }
}
