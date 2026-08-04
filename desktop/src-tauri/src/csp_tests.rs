//! Guards on the packaged-app Content-Security-Policy in `tauri.conf.json`.
//!
//! The CSP is only enforced on assets Tauri itself serves, so neither
//! `just dev` (loads the Vite `devUrl`) nor the Playwright suite (runs under
//! `vite preview`) can catch a policy that breaks the app. These tests pin the
//! non-obvious sources the frontend actually needs, so a future tightening
//! fails here instead of in a signed build.

use std::collections::HashMap;

const TAURI_CONF: &str = include_str!("../tauri.conf.json");

fn csp_directives() -> HashMap<String, Vec<String>> {
    let conf: serde_json::Value =
        serde_json::from_str(TAURI_CONF).expect("tauri.conf.json is valid JSON");
    let csp = conf["app"]["security"]["csp"]
        .as_str()
        .expect("app.security.csp is set as a policy string");

    csp.split(';')
        .filter_map(|directive| {
            let mut parts = directive.split_whitespace();
            let name = parts.next()?;
            Some((name.to_owned(), parts.map(str::to_owned).collect()))
        })
        .collect()
}

fn sources(directive: &str) -> Vec<String> {
    csp_directives()
        .remove(directive)
        .unwrap_or_else(|| panic!("csp is missing the {directive} directive"))
}

#[test]
fn script_src_allows_wasm_instantiation() {
    // Shiki's default engine (Oniguruma) instantiates inlined WebAssembly for
    // every code block; MediaPipe selfie segmentation does the same. Without
    // this token both silently degrade — highlighting drops to plain text and
    // animated avatars keep their background.
    assert!(sources("script-src").contains(&"'wasm-unsafe-eval'".to_owned()));
}

#[test]
fn script_src_allows_the_mediapipe_loader_cdn() {
    // `animatedAvatarCapture.ts` loads the pinned tasks-vision wasm loader from
    // jsDelivr. The 32MB asset set is too large to vendor, so the CDN origin
    // stays allowlisted; self-hosting it would let this source be dropped.
    assert!(sources("script-src").contains(&"https://cdn.jsdelivr.net".to_owned()));
}

#[test]
fn media_directives_allow_the_buzz_media_scheme() {
    // `rewriteRelayUrl` emits `buzz-media://localhost/...` until the loopback
    // proxy port resolves, so cold-start media renders through the custom
    // scheme (mapped to `http://buzz-media.localhost` on Windows).
    for directive in ["img-src", "media-src", "connect-src"] {
        let allowed = sources(directive);
        assert!(
            allowed.contains(&"buzz-media:".to_owned()),
            "{directive} must allow buzz-media:"
        );
        assert!(
            allowed.contains(&"http://buzz-media.localhost".to_owned()),
            "{directive} must allow http://buzz-media.localhost"
        );
    }
}

#[test]
fn connect_src_allows_ipc_and_cleartext_relays() {
    // `ipc:` / `http://ipc.localhost` carry every Tauri command. Cleartext
    // `http:`/`ws:` stay allowed because a relay URL is user-supplied and the
    // app accepts plain `ws://` on any host (`communityStorage::normalizeRelayUrl`,
    // the community edit form): `relayProbe` opens a browser WebSocket to it,
    // so narrowing this to loopback would report reachable relays as dead —
    // while the real connection, which runs through tauri-plugin-websocket in
    // Rust, is not governed by CSP at all. Blanket `https:` is already allowed,
    // so restricting the cleartext schemes would close no exfiltration path.
    let allowed = sources("connect-src");
    for source in [
        "ipc:",
        "http://ipc.localhost",
        "https:",
        "http:",
        "wss:",
        "ws:",
    ] {
        assert!(
            allowed.contains(&source.to_owned()),
            "connect-src must allow {source}"
        );
    }
}

#[test]
fn script_src_stays_free_of_unsafe_inline_and_eval() {
    let allowed = sources("script-src");
    // The inline boot script in index.html is covered by Tauri's build-time
    // sha256 hashing, so neither escape hatch is ever needed here.
    assert!(!allowed.contains(&"'unsafe-inline'".to_owned()));
    assert!(!allowed.contains(&"'unsafe-eval'".to_owned()));
}
