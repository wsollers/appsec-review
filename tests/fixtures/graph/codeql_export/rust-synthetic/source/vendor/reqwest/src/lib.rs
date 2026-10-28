//! Offline stand-in for the reqwest blocking API surface the fixture uses.
pub mod blocking {
    pub mod client {
        pub struct Client;

        pub struct RequestBuilder;

        impl Client {
            pub fn new() -> Client {
                Client
            }

            pub fn request(&self, method: &str, url: &str) -> RequestBuilder {
                let _ = (method, url);
                RequestBuilder
            }
        }
    }

    pub mod response {
        pub struct Response;

        impl Response {
            pub fn text(&self) -> Result<&'static str, ()> {
                Ok("")
            }
        }
    }

    pub use client::Client;
    pub use response::Response;

    pub fn get(url: &str) -> Result<Response, ()> {
        let _ = url;
        Ok(Response)
    }
}
