//! Docker TCP liveness probe; keeps the runtime independent of shell utilities.

use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], 5000));
    match TcpStream::connect_timeout(&address, Duration::from_secs(4)) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Floria listener unavailable: {error}");
            ExitCode::FAILURE
        }
    }
}
