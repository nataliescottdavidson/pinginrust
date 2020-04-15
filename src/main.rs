use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let hostname = &args[1]

    println!("{:?}", args);
}
