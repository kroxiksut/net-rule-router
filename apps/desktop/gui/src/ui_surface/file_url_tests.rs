use std::path::Path;

use super::path_to_file_url;

#[test]
fn drive_path_gets_three_slashes_and_forward_separators() {
    assert_eq!(
        path_to_file_url(Path::new(r"C:\Users\dev\ctx.json")),
        "file:///C:/Users/dev/ctx.json"
    );
}

#[test]
fn absolute_unix_path_keeps_its_leading_slash() {
    assert_eq!(
        path_to_file_url(Path::new("/tmp/ctx.json")),
        "file:///tmp/ctx.json"
    );
}

#[test]
fn url_delimiters_and_escapes_in_a_path_are_encoded() {
    assert_eq!(
        path_to_file_url(Path::new(r"C:\Users\C#dev\a b\50%?.json")),
        "file:///C:/Users/C%23dev/a%20b/50%25%3F.json"
    );
}

#[test]
fn non_ascii_is_encoded_as_utf8_bytes() {
    assert_eq!(
        path_to_file_url(Path::new("/home/\u{0438}")),
        "file:///home/%D0%B8"
    );
}
