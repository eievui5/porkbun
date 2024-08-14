#![warn(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    #[error("porkbun API returned an unrecognized response ({response})")]
    MalformedApi { response: String },
    #[error("porkbun API returned an unrecognized response ({response}): {error}")]
    MalformedApiSerde {
        error: serde_json::Error,
        response: String,
    },

    #[error("porkbun API returned an ipv4 address ({0}) when an ipv6 was expected")]
    UnexpectedIpv4(Ipv4Addr),
    #[error("porkbun API returned an ipv6 address ({0}) when an ipv4 was expected")]
    UnexpectedIpv6(Ipv6Addr),
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

macro_rules! typed_record {
    ($name:ident, $field:ident, $type:ty) => {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        pub struct $name {
            pub id: String,
            pub name: String,
            #[serde(rename = "content")]
            pub $field: $type,
            pub ttl: String,
            pub prio: String,
            pub notes: Option<String>,
        }
    };
}

typed_record!(Ipv4Record, address, Ipv4Addr);
typed_record!(Ipv6Record, address, Ipv6Addr);

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

    /// Tests authentication and returns the ip address used to make the request.
    ///
    /// This will almost always be an ipv6 address. Use [ping_ipv4] to recieve an ipv4 address.
    pub fn ping(&self) -> Result<Option<IpAddr>> {
        self.ping_url("https://api.porkbun.com/api/json/v3/ping")
    }

    /// Tests authentication and returns the ipv4 address used to make the request.
    pub fn ping_ipv4(&self) -> Result<Option<Ipv4Addr>> {
        match self.ping_url("https://api-ipv4.porkbun.com/api/json/v3/ping") {
            Ok(Some(IpAddr::V4(ip))) => Ok(Some(ip)),
            Ok(Some(IpAddr::V6(ip))) => Err(Error::UnexpectedIpv6(ip)),
            Ok(None) => Ok(None),
            Err(msg) => Err(msg),
        }
    }

    /// Tests authentication and returns the ipv6 address used to make the request.
    pub fn ping_ipv6(&self) -> Result<Option<Ipv6Addr>> {
        match self.ping_url("https://api.porkbun.com/api/json/v3/ping") {
            Ok(Some(IpAddr::V4(ip))) => Err(Error::UnexpectedIpv4(ip)),
            Ok(Some(IpAddr::V6(ip))) => Ok(Some(ip)),
            Ok(None) => Ok(None),
            Err(msg) => Err(msg),
        }
    }

    fn ping_url(&self, url: &str) -> Result<Option<IpAddr>> {
        #[derive(Clone, Debug, serde::Deserialize)]
        struct PingResponse {
            status: Status,
            #[serde(default)]
            message: String,
            #[serde(rename = "yourIp")]
            ip: Option<IpAddr>,
        }

        #[cfg(feature = "tracing")]
        tracing::info!("POST {url}");
        let response = self
            .client
            .post(url)
            .body(self.key_file.clone())
            .send()?
            .text()?;
        #[cfg(feature = "tracing")]
        tracing::info!("response: {response}");
        let response: PingResponse = serde_json::from_str(&response)
            .map_err(|error| Error::MalformedApiSerde { error, response })?;
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
    fn fetch_records_url<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<Vec<T>> {
        #[cfg(feature = "tracing")]
        tracing::info!("POST {url}");
        let response = self
            .client
            .post(url)
            .body(self.key_file.clone())
            .send()?
            .text()?;
        #[cfg(feature = "tracing")]
        tracing::info!("response: {response}");
        let object = match serde_json::from_str::<serde_json::Value>(&response) {
            Ok(object) => object,
            Err(error) => return Err(Error::MalformedApiSerde { error, response }),
        };
        let error = Error::MalformedApi { response };
        let Some(object) = object.as_object() else {
            return Err(error);
        };
        let Some(status) = object
            .get("status")
            .and_then(serde_json::Value::as_str)
            .and_then(|x| match x {
                "SUCCESS" => Some(Status::Success),
                "ERROR" => Some(Status::Error),
                _ => None,
            })
        else {
            return Err(error);
        };
        #[cfg(feature = "tracing_debug")]
        tracing::debug!("parsed response: {response:?}");

        match status {
            Status::Success => Ok(serde_json::from_value(
                object.get("records").ok_or(error)?.to_owned(),
            )?),
            Status::Error => Err(Error::Api {
                message: object
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(error)?
                    .to_string(),
            }),
        }
    }

    /// Fetches all DNS records for a given domain.
    ///
    /// These can be of any type and with any name.
    /// Consider using a more specific method if you're only interested in certain records,
    /// such as:
    /// - [Client::fetch_ipv4_records]
    /// - [Client::fetch_ipv6_records]
    pub fn fetch_records(&self, domain: &str) -> Result<Vec<DnsRecord>> {
        let url = format!("https://api.porkbun.com/api/json/v3/dns/retrieve/{domain}");
        self.fetch_records_url(&url)
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
        self.fetch_records_url(&url)
    }

    /// Fetches all DNS AAAA records for a given domain.
    pub fn fetch_ipv6_records(
        &self,
        domain: &str,
        subdomain: Option<&str>,
    ) -> Result<Vec<Ipv6Record>> {
        let mut url =
            format!("https://api.porkbun.com/api/json/v3/dns/retrieveByNameType/{domain}/AAAA/");
        if let Some(subdomain) = subdomain {
            url.push_str(subdomain);
        }
        self.fetch_records_url(&url)
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
            .map_err(|error| Error::MalformedApiSerde { error, response })?;
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
    fn edit_record_url<T: serde::Serialize>(&self, url: &str, ty: &str, content: &T) -> Result<()> {
        #[derive(Clone, Debug, serde::Deserialize)]
        struct EditDnsRecordResponse {
            status: Status,
            #[serde(default)]
            message: String,
        }

        let body = format!(
            "{{\"secretapikey\":{},\"apikey\":{},\"type\":{},\"content\":{}}}",
            self.secret_api_key,
            self.api_key,
            ty,
            serde_json::to_string(content)?
        );

        #[cfg(feature = "tracing")]
        tracing::info!("POST {url}");
        let response = self.client.post(url).body(body).send()?.text()?;
        #[cfg(feature = "tracing")]
        tracing::info!("response: {response}");
        let response: EditDnsRecordResponse = serde_json::from_str(&response)
            .map_err(|error| Error::MalformedApiSerde { error, response })?;
        #[cfg(feature = "tracing_debug")]
        tracing::debug!("parsed response: {response:?}");
        match response.status {
            Status::Success => Ok(()),
            Status::Error => Err(Error::Api {
                message: response.message,
            }),
        }
    }

    pub fn edit_ipv4_address(
        &self,
        domain: &str,
        subdomain: Option<&str>,
        address: &Ipv4Addr,
    ) -> Result<()> {
        let mut url = format!("https://api.porkbun.com/api/json/v3/dns/editByNameType/{domain}/A/");
        if let Some(subdomain) = subdomain {
            url.push_str(subdomain);
        }
        self.edit_record_url(&url, "A", address)
    }

    pub fn edit_ipv6_address(
        &self,
        domain: &str,
        subdomain: Option<&str>,
        address: &Ipv6Addr,
    ) -> Result<()> {
        let mut url = format!("https://api.porkbun.com/api/json/v3/dns/editByNameType/{domain}/A/");
        if let Some(subdomain) = subdomain {
            url.push_str(subdomain);
        }
        self.edit_record_url(&url, "A", address)
    }
}
