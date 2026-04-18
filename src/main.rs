mod command_arguments;
mod tls_server_config;

use crate::command_arguments::CommandArguments;
use anyhow::{anyhow, bail};
use clap::Parser;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{self, split, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::{TlsAcceptor, TlsStream};
use uuid::Uuid;

// References:
// https://postgresconf.org/system/events/document/000/000/183/pgconf_us_v4.pdf
// https://www.tzeejay.com/blog/2022/06/golang-postgresql-check-certificates
// https://www.postgresql.org/docs/current/ssl-tcp.html
// https://www.postgresql.org/docs/current/libpq-ssl.html
// https://xnuter.medium.com/writing-a-modern-http-s-tunnel-in-rust-56e70d898700
// https://ocw.mit.edu/courses/6-875-cryptography-and-cryptanalysis-spring-2005/
// https://tailscale.com/blog/introducing-pgproxy
// AWS - Aurora / RDS: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
// Google - Cloud SQL: https://github.com/brianc/node-postgres-docs/issues/79#issuecomment-1553759056

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: CommandArguments = CommandArguments::parse();
    // We observed that the program would output nothing (stdout/stderr) upon tracing init failure,
    // when using stderr as the writer.
    // Let's panic when we fail to initialize tracing, which will surely print to stderr.
    let tls_server_config = tls_server_config::server_config(
        &args.server_certificate_path,
        &args.server_private_key_path,
    )?;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", &args.server_port)).await?;
    while let Ok((inbound_tcp_stream, _)) = listener.accept().await {
        let request_id = Uuid::new_v4().to_string();

        let request_id_for_task = request_id.clone();
        let task = tokio::spawn(
            handle_inbound_request(
                inbound_tcp_stream,
                tls_server_config.clone(),
                args.client_connection_host_or_ip.to_owned(),
                args.client_connection_port.to_owned(),
                request_id_for_task,
            ),
        );

        let request_id_for_join = request_id.clone();
        tokio::spawn(async move {
            match task.await {
                Ok(Ok(())) => {
                }
                Ok(Err(e)) => {
                }
                Err(e) => {
                }
            }
        });
    }

    bail!("Something went wrong with the listener! Exiting program.")
}

async fn handle_inbound_request(
    inbound_stream: TcpStream,
    server_config: ServerConfig,
    connection_host_or_ip: String,
    connection_port: String,
    request_id: String,
) -> anyhow::Result<()> {
    let inbound_tls_stream = inbound_handshake(inbound_stream, server_config, &request_id).await?;
    let outbound_connect = outbound_connection(
        &connection_host_or_ip,
        &connection_port,
    )
    .await?;
    join(inbound_tls_stream, outbound_connect, &request_id).await?;

    Ok(())
}

async fn inbound_handshake(
    mut inbound_stream: TcpStream,
    server_config: ServerConfig,
    request_id: &str,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let mut buffer = [0u8; 8];
    inbound_stream.read_exact(&mut buffer).await?;
    if !buffer.starts_with(&[0, 0, 0, 8, 4, 210, 22, 47]) {
        // tell pgClient we do not support plaintext connections
        inbound_stream.write_all(b"N").await?;
        let err_msg = "TLS not supported by PG client on inbound connection";
        bail!("{err_msg}. RequestId: {request_id}");
    }
    // tell pgClient we're proceeding with TLS
    inbound_stream.write_all(b"S").await?;

    let stream = TlsAcceptor::from(Arc::new(server_config))
        .accept(inbound_stream)
        .await?
        .into();

    Ok(stream)
}

async fn outbound_connection(
    connection_host_or_ip: &str,
    connection_port: &str,
) -> anyhow::Result<TcpStream> {
    let connect_to = format!("{}:{}", connection_host_or_ip, connection_port);
    let connect_to = connect_to
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow!("Invalid address: {connect_to:?}"))?;
    let outbound_stream = TcpStream::connect(connect_to).await?;
    Ok(outbound_stream)
}

async fn join(
    inbound: TlsStream<TcpStream>,
    outbound: TcpStream,
    request_id: &str,
) -> anyhow::Result<()> {
    let (mut ir, mut iw) = split(inbound);
    let (mut or, mut ow) = split(outbound);

    let result = tokio::try_join!(io::copy(&mut ir, &mut ow), io::copy(&mut or, &mut iw));

    match result {
        Ok(_) => {
            Ok(())
        }
        Err(e) => {
            Err(e.into())
        }
    }
}
