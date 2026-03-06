use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::io::Write;
use std::thread;
use std::time::Duration;
use std::env;
use threadpool::ThreadPool;
use crossbeam::channel::{unbounded, Sender};
use log::info;

pub struct TcpServer {
    listener: TcpListener,
    thread_pool: ThreadPool,
    connection_counter: Arc<AtomicUsize>,
}

impl TcpServer {
    pub fn new() -> std::io::Result<Self> {
        let port: u16 = env::var("TCP_PORT")
            .unwrap_or_else(|_| "4987".to_string())
            .parse()
            .unwrap_or(4987);
        
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
        info!("TCP server listening on port {}", port);
        
        let pool_size = num_cpus::get() * 2;
        let thread_pool = ThreadPool::new(pool_size);
        
        Ok(TcpServer {
            listener,
            thread_pool,
            connection_counter: Arc::new(AtomicUsize::new(0)),
        })
    }
    
    pub fn run(self) {
        let (tx, rx) = unbounded::<Arc<AtomicUsize>>();
        
        // Spawn the listener thread
        let counter = self.connection_counter.clone();
        thread::spawn(move || {
            for stream in self.listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let counter = counter.clone();
                        let tx = tx.clone();
                        
                        // Increment connection counter
                        counter.fetch_add(1, Ordering::SeqCst);
                        
                        self.thread_pool.execute(move || {
                            handle_connection(stream, counter.clone(), tx);
                            // Decrement when connection closes
                            counter.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) => {
                        log::error!("Error accepting connection: {}", e);
                    }
                }
            }
        });
        
        // Handle periodic broadcasts (this will block)
        while let Ok(counter) = rx.recv() {
            // The actual broadcasting happens in handle_connection
            let _ = counter; // Consume to avoid warning
        }
    }
}

fn handle_connection(mut stream: TcpStream, counter: Arc<AtomicUsize>, _tx: Sender<Arc<AtomicUsize>>) {
    info!("New TCP connection from: {:?}", stream.peer_addr());
    
    // Send connection count every 10 seconds
    loop {
        let active_connections = counter.load(Ordering::SeqCst);
        let message = format!("Active connections: {}\n", active_connections);
        
        match stream.write_all(message.as_bytes()) {
            Ok(_) => {
                let _ = stream.flush();
            }
            Err(_) => {
                // Connection closed
                break;
            }
        }
        
        thread::sleep(Duration::from_secs(10));
    }
}