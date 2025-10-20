use reqwest::blocking::Client;
use serde_json::Value;
use std::net::{Ipv4Addr, Ipv6Addr};
use structopt::StructOpt;
use url::Url;

/// A simple command-line HTTP client similar to curl
#[derive(StructOpt, Debug)]
#[structopt(name = "curl")]
struct Opt {
    /// The URL to request
    url: String,

    /// HTTP method to use (GET or POST)
    #[structopt(short = "X", long)]
    method: Option<String>,

    /// Data to send in POST request (key=value pairs separated by &)
    #[structopt(short = "d", long)]
    data: Option<String>,

    /// JSON data to send in POST request
    #[structopt(long)]
    json: Option<String>,
}

fn main() {
    let opt = Opt::from_args();

    println!("Requesting URL: {}", opt.url);

    // Determine the HTTP method
    let method = if opt.json.is_some() {
        "POST"
    } else if let Some(ref m) = opt.method {
        m.as_str()
    } else {
        "GET"
    };

    println!("Method: {}", method);

    // Print data or JSON if provided
    if let Some(ref data) = opt.data {
        println!("Data: {}", data);
    }

    if let Some(ref json) = opt.json {
        println!("JSON: {}", json);
    }

    if let Err(e) = validate_url(&opt.url) {
        println!("Error: {}", e);
        return;
    }

    // Make the HTTP request
    match make_request(&opt.url, method, opt.data.as_deref(), opt.json.as_deref()) {
        Ok(body) => {
            if let Ok(json_value) = serde_json::from_str::<Value>(&body) {
                println!("Response body (JSON with sorted keys):");
                print_sorted_json(&json_value);
            } else {
                println!("Response body:");
                println!("{}", body);
            }
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}

/// Validate the URL for common errors
fn validate_url(url_str: &str) -> Result<(), String> {
    // Check for IPv6 address format first (before parsing)
    if url_str.contains('[') && url_str.contains(']') {
        if let Some(start) = url_str.find('[') {
            if let Some(end) = url_str.find(']') {
                if end > start {
                    let ip_str = &url_str[start + 1..end];
                    if ip_str.parse::<Ipv6Addr>().is_err() {
                        return Err("The URL contains an invalid IPv6 address.".to_string());
                    }
                }
            }
        }
    }

    // Check for IPv4 address format (before parsing) and extract host from URL string
    if let Some(scheme_end) = url_str.find("://") {
        let after_scheme = &url_str[scheme_end + 3..];
        let host_part = if let Some(slash_pos) = after_scheme.find('/') {
            &after_scheme[..slash_pos]
        } else if let Some(colon_pos) = after_scheme.find(':') {
            &after_scheme[..colon_pos]
        } else {
            after_scheme
        };

        // Check if it looks like an IPv4 address
        if host_part.chars().all(|c| c.is_ascii_digit() || c == '.') && host_part.contains('.') {
            if host_part.parse::<Ipv4Addr>().is_err() {
                return Err("The URL contains an invalid IPv4 address.".to_string());
            }
        }
    }

    // Check for invalid port number in the raw string
    if let Some(port_pos) = url_str.rfind(':') {
        let after_host = if let Some(path_pos) = url_str.rfind('/') {
            port_pos > path_pos
        } else if let Some(bracket_pos) = url_str.rfind(']') {
            port_pos > bracket_pos
        } else {
            port_pos > 8 // After "https://"
        };

        if after_host {
            let port_str = &url_str[port_pos + 1..];
            if let Ok(port) = port_str.parse::<u32>() {
                if port > 65535 {
                    return Err("The URL contains an invalid port number.".to_string());
                }
            }
        }
    }

    // Try to parse the URL
    let parsed_url = match Url::parse(url_str) {
        Ok(url) => url,
        Err(_) => {
            return Err("The URL does not have a valid base protocol.".to_string());
        }
    };

    // Check if the scheme is http or https
    let scheme = parsed_url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("The URL does not have a valid base protocol.".to_string());
    }

    Ok(())
}

/// Make an HTTP request and return the response body
fn make_request(
    url: &str,
    method: &str,
    data: Option<&str>,
    json: Option<&str>,
) -> Result<String, String> {
    let client = Client::new();

    let response = if method == "POST" {
        if let Some(json_data) = json {
            // Validate JSON before sending
            let json_value: Value = serde_json::from_str(json_data)
                .unwrap_or_else(|e| panic!("Invalid JSON: Error({:?})", e.to_string()));

            // Send POST request with JSON
            client
                .post(url)
                .header("Content-Type", "application/json")
                .json(&json_value)
                .send()
        } else if let Some(form_data) = data {
            // Parse form data and send as form
            let mut form_map = std::collections::HashMap::new();
            for pair in form_data.split('&') {
                let parts: Vec<&str> = pair.split('=').collect();
                if parts.len() == 2 {
                    form_map.insert(parts[0], parts[1]);
                }
            }
            client.post(url).form(&form_map).send()
        } else {
            client.post(url).send()
        }
    } else {
        client.get(url).send()
    };

    match response {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return Err(format!("Request failed with status code: {}.", status.as_u16()));
            }

            match resp.text() {
                Ok(body) => Ok(body),
                Err(e) => Err(format!("Failed to read response body: {}", e)),
            }
        }
        Err(e) => {
            // Check if it's a connection error
            if e.is_connect() || e.is_timeout() {
                Err("Unable to connect to the server. Perhaps the network is offline or the server hostname cannot be resolved.".to_string())
            } else {
                Err(format!("Request failed: {}", e))
            }
        }
    }
}

/// Print JSON with sorted keys
fn print_sorted_json(value: &Value) {
    match value {
        Value::Object(map) => {
            println!("{{");
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);

            for (i, (key, val)) in entries.iter().enumerate() {
                print!("  \"{}\": ", key);
                match val {
                    Value::String(s) => print!("\"{}\"", s),
                    Value::Number(n) => print!("{}", n),
                    Value::Bool(b) => print!("{}", b),
                    Value::Null => print!("null"),
                    Value::Object(_) => print_sorted_json_inline(val),
                    Value::Array(_) => print_sorted_json_inline(val),
                }
                if i < entries.len() - 1 {
                    println!(",");
                } else {
                    println!();
                }
            }
            println!("}}");
        }
        Value::Array(arr) => {
            print!("[");
            for (i, val) in arr.iter().enumerate() {
                print_sorted_json_inline(val);
                if i < arr.len() - 1 {
                    print!(", ");
                }
            }
            println!("]");
        }
        _ => println!("{}", value),
    }
}

/// Print JSON value inline (without newlines)
fn print_sorted_json_inline(value: &Value) {
    match value {
        Value::String(s) => print!("\"{}\"", s),
        Value::Number(n) => print!("{}", n),
        Value::Bool(b) => print!("{}", b),
        Value::Null => print!("null"),
        Value::Object(map) => {
            print!("{{");
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            for (i, (key, val)) in entries.iter().enumerate() {
                print!("\"{}\": ", key);
                print_sorted_json_inline(val);
                if i < entries.len() - 1 {
                    print!(", ");
                }
            }
            print!("}}");
        }
        Value::Array(arr) => {
            print!("[");
            for (i, val) in arr.iter().enumerate() {
                print_sorted_json_inline(val);
                if i < arr.len() - 1 {
                    print!(", ");
                }
            }
            print!("]");
        }
    }
}
