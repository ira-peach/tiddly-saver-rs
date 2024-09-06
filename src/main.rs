#![allow(unused)]
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
use std::env::Args;
use std::collections::VecDeque;
use std::io::Read;
use std::io;
use std::fs;
use std::fs::File;
use std::time::SystemTime;
use std::process::exit;

use base64::prelude::*;
use chrono::DateTime;
use chrono::Days;
use chrono::Utc;
use password_auth::generate_hash;
use password_auth::verify_password;
use regex::Regex;
use rouille::Request;
use rouille::Response;
use rouille::post_input;
use rouille::try_or_400;
use sha2::{Sha512, Digest};
use sqlite;
use sqlite::Connection;
use sqlite::State;
use sqlite::ReadableWithIndex;
use rand::distributions::Alphanumeric;
use rand::Rng;

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

#[derive(Clone,Debug,Default)]
struct RuntimeOptions {
    debug: bool,
    verbose: bool,
    recreate_admin: bool,
    database_path: Option<&'static str>,
}

#[derive(Clone,Debug)]
struct CredentialInfo {
    user_name: String,
    password_hash: String,
    password_salt: String,
}

impl CredentialInfo {
    pub fn new(user_name: String, password_hash: String, password_salt: String) -> CredentialInfo {
        CredentialInfo {
            user_name,
            password_hash,
            password_salt,
        }
    }
}

fn get_user_info(connection: &Connection, user: &str) -> Result<Option<CredentialInfo>,sqlite::Error> {
    let query = "SELECT password_hash, password_salt FROM user WHERE name = ?;";
    let mut statement = connection.prepare(query)?;
    statement.bind((1, user))?;
    let info = match statement.next()? {
        State::Row => {
            eprintln!("INFO: get_user_info(): found user '{}'", user);
            let hash = statement.read::<String, _>("password_hash")?;
            let salt = statement.read::<String, _>("password_salt")?;
            Some(CredentialInfo::new(user.to_owned(), hash, salt))
        },
        State::Done => {
            eprintln!("WARNING: get_user_info(): user '{}' does not exist", user);
            None
        },
    };
    Ok(info)
}

fn is_authenticated(connection: &Connection, session_id: &str) -> Result<bool,sqlite::Error> {
    let query = "SELECT session_id, expires_utc FROM authentication WHERE session_id = ?;";
    let mut statement = connection.prepare(query)?;
    statement.bind((1, session_id))?;
    match statement.next()? {
        State::Row => {
            let db_session_id = statement.read::<String, _>("session_id")?;
            let expires_utc = statement.read::<String, _>("expires_utc")?;
            let expires_utc = DateTime::parse_from_rfc3339(&expires_utc).unwrap();
            let now = SystemTime::now();
            let now: DateTime<Utc> = now.into();
            let within_expiry = now < expires_utc;
            if !within_expiry {
                eprintln!("WARNING: is_authenticated(): user session expired for '{}'", session_id);
            }
            return Ok(within_expiry);
        },
        State::Done => {
            eprintln!("WARNING: is_authenticated(): no session id found for '{}'", session_id);
            return Ok(false);
        },
    };
}

fn get_single<T: ReadableWithIndex>(connection: &Connection, query: &str, column: &str) -> Result<T,sqlite::Error> {
    let mut statement = connection.prepare(query)?;
    statement.next()?;
    let result = statement.read::<T, _>(column)?;
    Ok(result)
}

fn random_string(length: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(length).map(char::from).collect()
}

fn update_user(connection: &Connection, user: &str, salt: &str, hashed: &str) -> Result<(),sqlite::Error> {
    let mut statement = connection.prepare("UPDATE user SET password_salt=?, password_hash=? WHERE name=?;")?;
    statement.bind((1, salt))?;
    statement.bind((2, hashed))?;
    statement.bind((3, user))?;
    while State::Row == statement.next()? {
    }
    Ok(())
}

fn add_user(connection: &Connection, user: &str, salt: &str, hashed: &str) -> Result<(),sqlite::Error> {
    let mut statement = connection.prepare("INSERT INTO user (name, password_hash, password_salt) VALUES (?, ?, ?);")?;
    statement.bind((1, user))?;
    statement.bind((2, hashed))?;
    statement.bind((3, salt))?;
    while State::Row == statement.next()? {
    }
    Ok(())
}

use sqlite::ConnectionThreadSafe;

/// Salt and hash a password
///
/// For our application purposes, we use the salt+hash as the real password to verify
/// against, feeding into password_auth::verify_password.
///
/// This consumes password as a String, because we do not normally wish to reuse the
/// password value.  For the salt, we can borrow it safely.
///
/// In instances where you are generating a password, just clone the string.
///
/// Because of semantic overload, "hash", "salted hash", and "password hash" mean
/// related but importantly distring things in this crate.
///
/// The term "hash" refers to to a simple sha512 hash (or any other cryptographic hash,
/// for the future), "salted hash" refers to such a hash after prepending a salt, and
/// "password hash" or "pw hash" refers to the password_auth hash generated by
/// password_auth::generate_hash (and stored in the database).
///
/// Do *not* store the hash or salted hash on disk (or anywhere else at rest)!  Only store
/// the password hash!  I prefer only ever keeping a salted hash in memory if I must.
///
/// TODO: Figure out if this is the best way; I'd like to at least hash it unsalted, and
/// then maybe use the hash plus salt to make the salted hash, if that is better, but I
/// haven't had to actually handle secret data in a hobby application before.
///
/// TODO: Research if dictionary attacks against sha512 strings exist.
///
/// TODO: Figure out if it's better to hash on the client side and send; with TLS, it
/// shouldn't matter, but maybe it does?  In this case, salting and hashing the received
/// hash might be beneficial.
///
/// TODO: Figure out a use for `secrets` crate to enhance protection.
///
/// TODO: Figure out if this is possibly more ergonomic in any way, shape, or form,
/// because all this is clunky af.
fn salt_and_hash(salt: &str, password: String) -> String {
    sha512(format!("{}{}", salt, password))
}

/// Generate password and salt.
///
/// Generates a string of 12 characters each.
fn generate_password_and_salt() -> (String, String) {
    let password = random_string(12);
    let salt = random_string(12);
    (password, salt)
}

/// Generate password, salt, and salted hash.
///
/// Use this when needing to generate a user's password and display it to them.
///
/// See also generate_password_and_salt().
fn generate_password_salt_and_salted_hash() -> (String, String, String) {
    let (password, salt) = generate_password_and_salt();
    let salted_hash = salt_and_hash(&salt, password.clone());
    (password, salt, salted_hash)
}

/// Initialize database, if needed, creating the admin user if needed or requested.
///
/// The admin user's password will be printed to STDOUT if it is created.
///
/// This gives a thread-safe connection for Rouille to use as much as it wants.  Hopefully
/// the sqlite crate's implementation isn't unsound.  Otherwise, I will cry.
fn init_db(path: &str, recreate_admin: bool) -> Result<ConnectionThreadSafe, sqlite::Error> {
    let connection = Connection::open_thread_safe("tiddly-saver-rs.sqlite")?;
    connection.execute("CREATE TABLE IF NOT EXISTS user (user_id INT PRIMARY KEY, name TEXT UNIQUE, password_hash TEXT, password_salt TEXT);")?;
    connection.execute("CREATE TABLE IF NOT EXISTS authentication (authentication_id INT PRIMARY KEY, user_id INT, session_id TEXT UNIQUE, expires_utc TEXT);")?;
    let admin_count = get_single::<i64>(&connection, "SELECT COUNT(*) AS count FROM user WHERE name = 'admin';", "count")?;

    // We won't add or update ('upsert') in case of logic error; let sqlite error out.
    if admin_count == 0 {
        eprintln!("INFO: admin user does not exist.");

        let (password, salt, salted_hash) = generate_password_salt_and_salted_hash();
        let pw_hashed = generate_hash(&salted_hash);

        verify_password(salted_hash, &pw_hashed).expect("Password should have worked, but does not.  Not sure how to proceed besides crying.");

        add_user(&connection, "admin", &salt, &pw_hashed)?;
        println!("NOTICE: admin password is '{}'.  Please keep it safe (or update it after login).", password);
    }
    else if recreate_admin {
        eprintln!("INFO: Re-creating admin user as requested");

        let (password, salt, salted_hash) = generate_password_salt_and_salted_hash();
        let pw_hashed = generate_hash(&salted_hash);

        verify_password(salted_hash, &pw_hashed).expect("Password should have worked, but does not.  Not sure how to proceed besides crying.");

        update_user(&connection, "admin", &salt, &pw_hashed)?;
        println!("NOTICE: admin password is '{}'.  Please keep it safe (or update it after login).", password);
    }

    Ok(connection)
}

fn etag_from_path(path: &str) -> io::Result<String> {
    let data = read_file(path)?;
    return Ok(sha512(&data));
}

fn sha512(data: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha512::new();
    hasher.update(&data);
    let result = hasher.finalize();
    let etag = format!("{:02x}", result);
    return etag;
}

fn read_file(path: &str) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let data = read_data(file)?;
    return Ok(data);
}

fn read_data(mut file: File) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    return Ok(data);
}

fn bad_request_with(msg: String) -> Response {
    let body = format!("<h1>400 BAD REQUEST</h1>{}", msg);
    Response::html(template("400 BAD REQUEST", &body)).with_status_code(400)
}

fn bad_request() -> Response {
    let body = "<h1>400 BAD REQUEST</h1>";
    Response::html(template("400 BAD REQUEST", &body)).with_status_code(400)
}

fn unauthorized() -> Response {
    Response::html(template("401 UNAUTHORIZED", "<h1>401 UNAUTHORIZED</h1><p>Please authenticate</p>")).with_status_code(401)
}

fn unauthorized_with(body: &str) -> Response {
    let body = format!("<h1>401 UNAUTHORIZED</h1><p>{}</p>", body);
    Response::html(template("401 UNAUTHORIZED", &body)).with_status_code(401)
}

fn add_user_authentication(connection: &Connection, user: &str, session_id: &str, expires_absolute: &str) -> Result<(),sqlite::Error> {
    let mut statement = connection.prepare("SELECT user_id FROM user WHERE name = ?;")?;
    statement.bind((1, user))?;
    let user_id = match statement.next()? {
        State::Row => statement.read::<i64, _>("user_id")?,
        State::Done => {
            panic!("ERROR: add_user_authentication(): this shouldn't happen, but user does not exist for {}", user);
        },
    };

    let mut statement = connection.prepare("INSERT INTO authentication (user_id, session_id, expires_utc) VALUES (?, ?, ?);")?;
    statement.bind((1, user))?;
    statement.bind((2, session_id))?;
    statement.bind((3, expires_absolute))?;
    while let State::Row = statement.next()? {
    }

    Ok(())
}

fn authenticate(connection: &Connection, request: &Request, dry_run: bool) -> Response {
    let input = post_input!(request, {
        user: String,
        password: String,
    });
    let input = match input {
        Ok(input) => input,
        Err(err) => {
            eprintln!("WARNING: bad request during authenticate(): {}", err);
            return bad_request_with(err.to_string());
        },
    };
    let user = input.user;
    let user_info = match get_user_info(&connection, &user) {
        Err(err) => {
            eprintln!("ERROR: getting user info: {}", err);
            return internal_server_error();
        },
        Ok(None) => {
            eprintln!("WARNING: authenticate(): user '{}' not found", user);
            return unauthorized_with("Could not log in; please <a href=\"/login\">try again</a>.");
        },
        Ok(Some(user_info)) => user_info,
    };
    let salted_hash = salt_and_hash(&user_info.password_salt, input.password);
    let authenticated = match verify_password(salted_hash, &user_info.password_hash) {
        Err(err) => {
            use password_auth::VerifyError::Parse;
            use password_auth::VerifyError::PasswordInvalid;
            match err {
                PasswordInvalid => false,
                Parse(err) => {
                    eprintln!("ERROR: authenticate(): {}", err);
                    return internal_server_error();
                },
            }
        },
        Ok(()) => true,
    };
    if !authenticated {
        return unauthorized_with("Could not log in; please <a href=\"/login\">try again</a>.");
    }
    let now = SystemTime::now();
    let now: DateTime<Utc> = now.into();
    let expires_relative = Days::new(7);
    let expires_relative_seconds = 7*24*60*60;
    let expires_absolute = match now.checked_add_days(expires_relative) {
        None => {
            eprintln!("ERROR: somehow we can't add 7 days to datetime '{}'", now);
            return internal_server_error();
        }
        Some(time) => time.to_rfc3339(),
    };
    let session_id = random_string(256);
    let session_id = sha512(format!("{},{}", expires_absolute, session_id));
    match add_user_authentication(connection, &user, &session_id, &expires_absolute) {
        Err(err) => {
            eprintln!("ERROR: during add_user_authentication(): {}", err);
            return internal_server_error();
        },
        Ok(()) => (),
    }
    let cookie = format!("__Host-session_id={}; Path=/; Secure; HttpOnly; Samesite=Strict", session_id);
    Response::html(template("LOGGED IN", "<h1>You are now logged in!  You may proceed to <a href=\"/index.html\">the wiki</a>!")).with_unique_header("Set-Cookie", cookie)
}

fn internal_server_error() -> Response {
    Response::html(template("500 INTERNAL SERVER ERROR", "<h1>500 INTERNAL SERVER ERROR</h1>")).with_status_code(500)
}

fn options_response(options: &str) -> Response {
    Response::text("").with_unique_header("allow", options.to_string())
}

fn method_not_allowed() -> Response {
    Response::html(template("405 METHOD NOT ALLOWED", "<p>405 METHOD NOT ALLOWED</p>")).with_status_code(405)
}

use rouille::input::cookies;

fn authorize(connection: &Connection, request: &Request) -> Result<(),Response> {
    let cookie_name = "__Host-session_id";
    let session_id = match cookies(&request).find(|&(n, _)| n == cookie_name) {
        None => {
            eprintln!("WARNING: authorize(): user cookie '{}' not found", cookie_name);
            return Err(unauthorized());
        },
        Some((_, session_id)) => session_id,
    };
    match is_authenticated(connection, session_id) {
        Err(err) => {
            eprintln!("ERROR: authorize(): for session id '{}': sqlite error: {}", session_id, err);
            return Err(internal_server_error());
        },
        Ok(false) => {
            eprintln!("WARNING: authorize(): user is not authenticated for session id '{}'", session_id);
            return Err(unauthorized());
        },
        Ok(true) => (),
    }
    Ok(())
}

fn delete_user_authentication(connection: &Connection, session_id: &str) -> Result<(),sqlite::Error> {
    let mut statement = connection.prepare("DELETE FROM authentication WHERE session_id = ?;")?;
    statement.bind((1, session_id))?;
    while let State::Row = statement.next()? {
    }
    Ok(())
}

fn logout(connection: &Connection, request: &Request) -> Result<(),Response> {
    let cookie_name = "__Host-session_id";
    let session_id = match cookies(&request).find(|&(n, _)| n == cookie_name) {
        None => {
            eprintln!("WARNING: authorize(): user cookie '{}' not found", cookie_name);
            return Err(unauthorized());
        },
        Some((_, session_id)) => session_id,
    };
    match delete_user_authentication(connection, &session_id) {
        Err(err) => {
            eprintln!("ERROR: logout(): sqlite error: {}", err);
            return Err(internal_server_error());
        },
        Ok(()) => (),
    }
    Ok(())
}

fn generate_response(connection: &Connection, request: &Request, runtime_options: &RuntimeOptions) -> Response {
    let method = request.method();
    let remote = request.remote_addr();
    let url_path = request.url();

    println!("INFO: connection from '{}': {} '{}'", remote, method, url_path);

    if runtime_options.debug {
        eprintln!("DEBUG: {:?}", request);
    }

    if url_path == "/" {
        if method == "GET" {
            return Response::redirect_303("/index.html");
        }
        else if method == "HEAD" {
            return Response::redirect_303("/index.html");
        }
        else if method == "OPTIONS" {
            return options_response("OPTIONS, GET, HEAD");
        }
        return method_not_allowed();
    }
    else if url_path == "/login" {
        if method == "GET" {
            return Response::html(template("Login", r#"<h1>Login</h1> <form method="POST"><div><label for="user">User:</label><input name="user" id=user /></div><div><label for="password">Password:</label><input name="password" id="password" type="password" /></div><div><button>Submit</button></div></form>"#));
        }
        else if method == "POST" {
            let response = authenticate(connection, request, false);
            return response;
        }
        else if method == "OPTIONS" {
            return options_response("OPTIONS, GET, POST");
        }
        return method_not_allowed();
    }
    else if url_path == "/logout" {
        if method == "GET" {
            logout(&connection, &request);
            return Response::html(template("Logged Out", "<h1>Logout</h1> <p>You are now logged out!</p>")).with_status_code(401);
        }
        else if method == "OPTIONS" {
            return options_response("OPTIONS, GET");
        }
        return method_not_allowed();
    }
    else if url_path == "/index.html" {
        if method == "GET" {
            let data = read_file("index.html");
            if let Err(err) = data {
                eprintln!("ERROR: could not read from 'index.html': {}", err);
                return internal_server_error();
            }
            let data = data.unwrap();
            let etag = sha512(&data);
            if runtime_options.debug {
                eprintln!("DEBUG: etag: {}", etag);
            }
            return Response::from_data("text/html", data).with_etag(request, etag);
        }
        else if method == "HEAD" {
            let data = read_file("index.html");
            if let Err(err) = data {
                eprintln!("ERROR: could not read from 'index.html': {}", err);
                return internal_server_error();
            }
            let data = data.unwrap();
            let etag = sha512(&data);
            if runtime_options.debug {
                eprintln!("DEBUG: etag: {}", etag);
            }
            return Response::text("").with_status_code(200).with_etag(request, etag);
        }
        else if method == "PUT" {
            let auth_result = authorize(&connection, &request);
            match auth_result {
                Err(response) => {
                    return response;
                },
                Ok(()) => (),
            }

            let now = SystemTime::now();
            let now: DateTime<Utc> = now.into();
            let now = now.to_rfc3339();
            let backup_name = format!("index-{}.html", now);
            let backup_name = backup_name.replace(":", "");
            let result = fs::copy("index.html", &backup_name);
            if let Err(err) = result {
                eprintln!("ERROR: trying to copy from '{}' to '{}': {}", "index.html", backup_name, err);
                return internal_server_error();
            }
            let data = request.data();
            if let Err(err) = result {
                eprintln!("ERROR: 0003: {}", err);
                return internal_server_error();
            }
            let mut data = data.unwrap();
            let mut buf = Vec::new();
            let result = data.read_to_end(&mut buf);
            if let Err(err) = result {
                eprintln!("ERROR: 0002: {}", err);
                return internal_server_error();
            }
            let content_etag = sha512(&buf);
            let etag = etag_from_path("index.html");
            if let Err(err) = etag {
                eprintln!("ERROR: trying to get etag from path 'index.html': {}", err);
                return internal_server_error();
            }
            let etag = etag.unwrap();
            if let Some(header_etag) = request.header("if-match") {
                if etag == content_etag {
                    if etag != header_etag {
                        println!("WARNING: request header etag does not match generated etag '{}'", etag);
                        // TODO: change savers/put.js in TiddlyWiki to use error 409 CONFLICT
                        // instead or in addition to.
                        //return Response::text("").with_status_code(412);
                        return Response::text("").with_status_code(409);
                    }
                    return Response::empty_204().with_etag(request, etag);
                }
            }
            let content = String::from_utf8(buf);
            if let Err(err) = content {
                eprintln!("ERROR: 0001: {}", err);
                return Response::html(template("400 BAD REQUEST", "<h1>400 BAD REQUEST</h1>")).with_status_code(400);
            }
            let content = content.unwrap();
            let result = fs::write("index.html", content);
            if let Err(err) = result {
                eprintln!("ERROR: 0005: {}", err);
                return internal_server_error();
            }
            return Response::empty_204().with_etag(request, etag);
        }
        else if method == "OPTIONS" {
            return Response::text("").with_unique_header("allow", "OPTIONS, GET, HEAD, PUT");
        }
        return Response::html(template("405 METHOD NOT ALLOWED", "<p>405 METHOD NOT ALLOWED</p>")).with_status_code(405);
    }
    else if method == "OPTIONS" {
        return Response::text("").with_unique_header("allow", "OPTIONS");
    }
    return Response::html(template("404 NOT FOUND", "<h1>404 NOT FOUND</h1>")).with_status_code(404);
}

fn parse_options(args: Args) -> Result<RuntimeOptions,String> {
    let short_opt_re = Regex::new(r"^-[0-9A-Za-z][0-9A-Za-z]+$").unwrap();
    let char_re = Regex::new(r".").unwrap();

    let mut runtime_options: RuntimeOptions = Default::default();
    runtime_options.debug = false;
    runtime_options.verbose = false;
    let mut args: VecDeque<_> = args.collect();
    let exe = args.pop_front();
    if exe.is_none() {
        return Err("somehow there is no executable for ARGV[0]".to_string());
    }

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
            if runtime_options.verbose {
                runtime_options.debug = true;
            }
            runtime_options.verbose = true;
        }
        else if arg == "--recreate-admin" {
            runtime_options.recreate_admin = true;
        }
        else if arg == "--no-recreate-admin" {
            runtime_options.recreate_admin = false;
        }
        else if arg == "--database" {
            let path = match args.pop_front() {
                None => {
                    eprintln!("ERROR: --database must have argument");
                    exit(1);
                },
                Some(path) => {
                    if path == "" {
                        eprintln!("ERROR: --database must have argument of at least one character");
                        exit(1);
                    }
                    path
                },
            };
            // We want to pass this string between all threads at any point, and will only
            // usually be created at most once; however, if multiple --database options
            // are called, we will link once per.  Usually a user isn't strange enough to
            // pass way too many of these to really impact the footprint, but could be an
            // interesting denial of service.
            //
            // The real fix is to use an interning library like `intern` to provide leak
            // safety here, or use something suitably large (like an array of 100 kB of
            // space) to store the string.
            //
            // Or, use Either from `either` crate with a String or &'static str.  Not sure
            // if that's Send, though.
            //
            // Discard from `discard` might also work here.
            let path = path.leak();
            runtime_options.database_path = Some(path);
        }
        else {
            return Err(format!("unexpected argument: '{}'", arg));
        }
    }

    if !args.is_empty() {
        let mut err = "unexpected remaining arguments:".to_string();
        for arg in args {
            err = format!("{} '{}'", err, arg.replace("'", "\\'"));
        }
        return Err(err);
    }
    return Ok(runtime_options);
}

fn main() {
    let args = env::args();
    let runtime_options = parse_options(args);
    if let Err(err) = runtime_options {
        eprintln!("ERROR: {}", err);
        exit(1);
    }
    let runtime_options = runtime_options.unwrap();

    let database_path = runtime_options.database_path.unwrap_or("tiddy-saver-rs.sqlite");
    let connection = init_db(&database_path, runtime_options.recreate_admin);
    if let Err(err) = connection {
        eprintln!("ERROR: {}", err);
        exit(1);
    }
    let connection = connection.unwrap();

    println!("You should be able to connect.  If on localhost, this should work:");
    println!();
    println!("  http://127.0.0.1:8082");

    rouille::start_server("0.0.0.0:8082", move |request| {
        let method = request.method();
        let remote = request.remote_addr();
        let url_path = request.url();
        let response = generate_response(&connection, &request, &runtime_options);

        println!("VERBOSE: returning response to '{}' for {} '{}': {}", remote, method, url_path, response.status_code);

        if runtime_options.debug {
            eprintln!("DEBUG: {:?}", response);
        }

        response
    });
}
