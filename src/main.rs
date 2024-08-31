// tiddly-saver-rs - implement server PutSaver for TiddlyWiki
// Copyright (C) 2024  Ira Peach
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use std::env;
use std::collections::VecDeque;
use std::io::Read;
use std::io::Result;
use std::fs;
use std::fs::File;
use std::time::SystemTime;

use chrono::DateTime;
use chrono::Utc;
use sha2::{Sha512, Digest};
use regex::Regex;
//use rouille::Request;
use rouille::Response;

fn template(title: &str, body: &str) -> String {
    format!(r##"<!doctype html>
<html lang="en-US">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width" />

    <title>{}</title>
    <link rel="stylesheet" href="style.css" />
  </head>

  <body>
{}
  </body>
</html>"##, title, body)
}

fn etag(data: &Vec<u8>) -> String {
    let mut hasher = Sha512::new();
    hasher.update(&data);
    let result = hasher.finalize();
    let etag = format!("{:02x}", result);
    return etag;
}

fn read_file(path: &str) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let data = read_data(file)?;
    return Ok(data);
}

fn read_data(mut file: File) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    return Ok(data);
}

fn main() {
    let short_opt_re = Regex::new(r"^-[0-9A-Za-z][0-9A-Za-z]+$").unwrap();
    let char_re = Regex::new(r".").unwrap();
    let mut debug = false;
    let mut verbose = false;
    let mut args: VecDeque<_> = env::args().collect();
    loop {
        let arg = args.pop_front();
        if arg.is_none() {
            break;
        }
        let arg = arg.unwrap();
        if arg == "--" {
            break;
        }
        else if short_opt_re.is_match(&arg) {
            let mut chars: VecDeque<&str> = char_re.find_iter(&arg).map(|m| m.as_str()).collect();
            let mut normalized: Vec<String> = Vec::new();
            while !chars.is_empty() {
                let c = chars.pop_front().unwrap();
                if c == "-" {
                    continue;
                }
                let mut new_string = String::from("-");
                new_string.push_str(c);
                normalized.push(new_string);
            }
            for n in normalized {
                args.push_front(n);
            }
            continue;
        }
        else if arg == "-v" || arg == "--verbose" {
            if verbose {
                debug = true;
            }
            verbose = true;
        }
    }

    println!("You should be able to connect.  If on localhost, this should work:");
    println!();
    println!("  http://127.0.0.1:8082");

    rouille::start_server("0.0.0.0:8082", move |request| {
        let method = request.method();
        let remote = request.remote_addr();
        let url_path = request.url();

        println!("INFO: connection from '{}': {} '{}'", remote, method, url_path);

        if debug {
            eprintln!("DEBUG: {:?}", request);
        }

        let response;

        if method == "GET" {
            if url_path == "/" {
                response = Response::redirect_303("/index.html");
            }
            else if url_path == "/index.html" {
                let data = read_file("index.html");
                if let Err(err) = data {
                    eprintln!("ERROR: could not read from 'index.html': {}", err);
                    response = Response::html(template("500 INTERNAL SERVER ERROR", "<h1>500 INTERNAL SERVER ERROR</h1>")).with_status_code(500);
                }
                else {
                    let data = data.unwrap();
                    let etag = etag(&data);
                    if debug {
                        eprintln!("DEBUG: etag: {}", etag);
                    }
                    response = Response::from_data("text/html", data).with_etag(request, etag);
                }
            }
            else {
                response = Response::html(template("404 NOT FOUND", "<h1>404 NOT FOUND</h1>")).with_status_code(404);
            }
        }
        else if method == "HEAD" {
            if url_path == "/" {
                response = Response::redirect_303("/index.html");
            }
            else if url_path == "/index.html" {
                let data = read_file("index.html");
                if let Err(err) = data {
                    eprintln!("ERROR: could not read from 'index.html': {}", err);
                    response = Response::html(template("500 INTERNAL SERVER ERROR", "<h1>500 INTERNAL SERVER ERROR</h1>")).with_status_code(500);
                }
                else {
                    let data = data.unwrap();
                    let etag = etag(&data);
                    if debug {
                        eprintln!("DEBUG: etag: {}", etag);
                    }
                    response = Response::text("").with_status_code(200).with_etag(request, etag);
                }
            }
            else {
                response = Response::html(template("404 NOT FOUND", "<h1>404 NOT FOUND</h1>")).with_status_code(404);
            }
        }
        else if method == "OPTIONS" {
            if url_path == "/index.html" {
                response = Response::text("").with_unique_header("allow", "OPTIONS, GET, HEAD, PUT").with_unique_header("dav", "1");
            }
            else if url_path == "*" {
                response = Response::text("").with_unique_header("allow", "OPTIONS, GET");
            }
            else {
                response = Response::text("").with_unique_header("allow", "OPTIONS, GET");
            }
        }
        else if method == "PUT" {
            if url_path == "/index.html" {
                let now = SystemTime::now();
                let now: DateTime<Utc> = now.into();
                let now = now.to_rfc3339();
                let backup_name = format!("index-{}.html", now);
                let backup_name = backup_name.replace(":", "");
                let result = fs::copy("index.html", &backup_name);
                if let Err(err) = result {
                    eprintln!("ERROR: trying to copy from '{}' to '{}': {}", "index.html", backup_name, err);
                    response = Response::html(template("500 INTERNAL SERVER ERROR", "<h1>500 INTERNAL SERVER ERROR</h1>")).with_status_code(500);
                }
                else {
                    let data = request.data();
                    if let Err(err) = result {
                        eprintln!("ERROR: 0003: {}", err);
                        response = Response::html(template("500 INTERNAL SERVER ERROR", "<h1>500 INTERNAL SERVER ERROR</h1>")).with_status_code(500);
                    }
                    else {
                        let mut data = data.unwrap();
                        let mut buf = Vec::new();
                        let result = data.read_to_end(&mut buf);
                        if let Err(err) = result {
                            eprintln!("ERROR: 0002: {}", err);
                            response = Response::html(template("500 INTERNAL SERVER ERROR", "<h1>500 INTERNAL SERVER ERROR</h1>")).with_status_code(500);
                        }
                        else {
                            let etag = etag(&buf);
                            let content = String::from_utf8(buf);
                            if let Err(err) = content {
                                eprintln!("ERROR: 0001: {}", err);
                                response = Response::html(template("400 INTERNAL SERVER ERROR", "<h1>400 BAD REQUEST</h1>")).with_status_code(400);
                            }
                            else {
                                let content = content.unwrap();
                                let result = fs::write("index.html", content);
                                if let Err(err) = result {
                                    eprintln!("ERROR: 0005: {}", err);
                                    response = Response::html(template("500 INTERNAL SERVER ERROR", "<h1>500 INTERNAL SERVER ERROR</h1>")).with_status_code(500);
                                }
                                else {
                                    response = Response::empty_204().with_etag(request, etag);
                                }
                            }
                        }
                        //let result = fs::write("index.html", data);
                    }
                }
            }
            else {
                response = Response::html(template("405 METHOD NOT ALLOWED", "<p>405 METHOD NOT ALLOWED</p>")).with_status_code(405);
            }
        }
        else {
            response = Response::html(template("405 METHOD NOT ALLOWED", "<p>405 METHOD NOT ALLOWED</p>")).with_status_code(405);
        }

        println!("VERBOSE: returning response to '{}' for {} '{}': {}", remote, method, url_path, response.status_code);

        if debug {
            eprintln!("DEBUG: {:?}", response);
        }

        response
    });
}
