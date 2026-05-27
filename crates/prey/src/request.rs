//! # Request module
//! The Request module of PREY framework contains all TCP request processing and parsing functions
//! to ease the later development of a WebServer.

// <! ------------------------------- STREAM MANAGEMENT ------------------------------------>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub method: RequestMethod,
    pub uri: String,
    pub headers: Vec<String>,
    pub header_amount: i32,
    pub body: String,
    pub raw_bytes: &'a [u8]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestMethod {
    GET,
    POST,
    PUT,
    PATCH,
    OPTION,
    DELETE,
    Other(String)
}

impl<'a> Request<'a> {
    pub fn new(raw: &'a [u8]) -> Request<'a> {

        let request_str = String::from_utf8_lossy(&raw);

        let mut parts = request_str.split("\r\n");

        let request_line = parts.next().unwrap();

        let method = request_line.split(" ").nth(0).unwrap();
        let uri = request_line.split(" ").nth(1).unwrap();

        println!("Method: {} | URI: {}", method, uri);

        let mut headers: Vec<String> = Vec::new();

        let mut header_count = 0;
        loop {
            let current_part = parts.next();

            if let Some(part) = current_part {
                println!("Part#{}: {}", header_count, part);
                header_count += 1;
                if part != "" {
                    headers.push(part.to_string());
                    continue;
                } else {
                    break;
                }
                
            } else {
                break;
            }
        }
        let body = parts.next().unwrap();

        Self {
            method: RequestMethod::from(method),
            uri: uri.to_string(),
            headers: headers,
            header_amount: header_count,
            body: body.to_string(),
            raw_bytes: raw
        }
    }
}

impl From<&str> for RequestMethod {
    fn from(value: &str) -> Self {
        match value {
            "GET" => RequestMethod::GET,
            "POST" => RequestMethod::POST,
            "PUT" => RequestMethod::PUT,
            "PATCH" => RequestMethod::PATCH,
            "DELETE" => RequestMethod::DELETE,
            "OPTION" => RequestMethod::OPTION,
            _ => RequestMethod::Other(value.to_string()),
        }
    }
}




// <! ------------------------------- PACKET MANAGEMENT ------------------------------------>

