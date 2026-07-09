//! Procedural cover art. Each generator emits Typst `place()` calls drawn
//! with primitive shapes only (lines, circles, polygons, text), so the art
//! is licence-free, offline, and infinitely variable via the seed.
//!
//! Canvas: the cover page content area, roughly 467pt x 690pt.

use std::fmt::Write as _;

const W: f64 = 467.0;
const H: f64 = 690.0;

/// Small xorshift RNG so we don't need a rand dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E3779B97F4A7C15).max(1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn f(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (self.next() >> 11) as f64 / (1u64 << 53) as f64 * (hi - lo)
    }

    fn chance(&mut self, p: f64) -> bool {
        self.f(0.0, 1.0) < p
    }
}

fn alpha(color: &str, a: u8) -> String {
    format!("{color}{a:02x}")
}

fn line(s: &mut String, x1: f64, y1: f64, x2: f64, y2: f64, width: f64, color: &str) {
    let _ = writeln!(
        s,
        "#place(top + left, line(start: ({x1:.1}pt, {y1:.1}pt), end: ({x2:.1}pt, {y2:.1}pt), stroke: {width:.2}pt + rgb(\"{color}\")))"
    );
}

fn circle(s: &mut String, cx: f64, cy: f64, r: f64, paint: &str) {
    let _ = writeln!(
        s,
        "#place(top + left, dx: {:.1}pt, dy: {:.1}pt, circle(radius: {r:.1}pt, {paint}))",
        cx - r,
        cy - r
    );
}

pub fn generate(style: &str, seed: u64, accent: &str, mono_font: &str) -> String {
    match style {
        "hexgrid" => hexgrid(seed, accent),
        "circuit" => circuit(seed, accent),
        "network" => network(seed, accent),
        "radar" => radar(seed, accent),
        "binary" => binary(seed, accent, mono_font),
        "contours" => contours(seed, accent),
        _ => String::new(),
    }
}

fn hexgrid(seed: u64, accent: &str) -> String {
    let mut rng = Rng::new(seed);
    let mut s = String::new();
    let r = 24.0;
    let stroke = alpha(accent, 0x24);
    let fill = alpha(accent, 0x30);
    // Flat-top hexagon vertices relative to the bounding-box top-left.
    let verts = |r: f64| -> String {
        let h = r * 0.866;
        format!(
            "({:.1}pt, {:.1}pt), ({:.1}pt, {:.1}pt), ({:.1}pt, {:.1}pt), ({:.1}pt, {:.1}pt), ({:.1}pt, {:.1}pt), ({:.1}pt, {:.1}pt)",
            r * 0.5, 0.0, r * 1.5, 0.0, r * 2.0, h, r * 1.5, 2.0 * h, r * 0.5, 2.0 * h, 0.0, h
        )
    };
    let mut row = 0;
    let mut y = -20.0;
    while y < H {
        let x_off = if row % 2 == 0 { 0.0 } else { r * 1.5 };
        let mut x = -30.0 + x_off;
        while x < W + 30.0 {
            if rng.chance(0.42) {
                let filled = rng.chance(0.12);
                let paint = if filled {
                    format!("fill: rgb(\"{fill}\")")
                } else {
                    format!("stroke: 0.7pt + rgb(\"{stroke}\")")
                };
                let _ = writeln!(
                    s,
                    "#place(top + left, dx: {x:.1}pt, dy: {y:.1}pt, polygon({paint}, {}))",
                    verts(r)
                );
            }
            x += r * 3.0;
        }
        y += r * 0.866;
        row += 1;
    }
    s
}

fn circuit(seed: u64, accent: &str) -> String {
    let mut rng = Rng::new(seed);
    let mut s = String::new();
    let trace = alpha(accent, 0x2c);
    let node = alpha(accent, 0x55);
    for _ in 0..16 {
        let mut x = rng.f(20.0, W - 20.0);
        let mut y = rng.f(20.0, H - 20.0);
        circle(&mut s, x, y, 2.6, &format!("fill: rgb(\"{node}\")"));
        let mut horizontal = rng.chance(0.5);
        let segments = 3 + (rng.next() % 3) as usize;
        for _ in 0..segments {
            let len = rng.f(40.0, 130.0) * if rng.chance(0.5) { 1.0 } else { -1.0 };
            let (nx, ny) = if horizontal {
                ((x + len).clamp(10.0, W - 10.0), y)
            } else {
                (x, (y + len).clamp(10.0, H - 10.0))
            };
            line(&mut s, x, y, nx, ny, 0.9, &trace);
            x = nx;
            y = ny;
            horizontal = !horizontal;
        }
        circle(&mut s, x, y, 2.6, &format!("fill: rgb(\"{node}\")"));
    }
    s
}

fn network(seed: u64, accent: &str) -> String {
    let mut rng = Rng::new(seed);
    let mut s = String::new();
    let edge = alpha(accent, 0x1e);
    let small = alpha(accent, 0x3c);
    let hub = alpha(accent, 0x66);
    let nodes: Vec<(f64, f64)> = (0..30)
        .map(|_| (rng.f(10.0, W - 10.0), rng.f(10.0, H - 10.0)))
        .collect();
    // Connect each node to its two nearest neighbours.
    for (i, &(x, y)) in nodes.iter().enumerate() {
        let mut dist: Vec<(f64, usize)> = nodes
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .map(|(j, &(nx, ny))| ((nx - x).powi(2) + (ny - y).powi(2), j))
            .collect();
        dist.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        for &(_, j) in dist.iter().take(2) {
            if j > i {
                let (nx, ny) = nodes[j];
                line(&mut s, x, y, nx, ny, 0.7, &edge);
            }
        }
    }
    for (i, &(x, y)) in nodes.iter().enumerate() {
        if i % 7 == 0 {
            circle(&mut s, x, y, 5.0, &format!("fill: rgb(\"{hub}\")"));
            circle(&mut s, x, y, 9.0, &format!("stroke: 0.7pt + rgb(\"{small}\")"));
        } else {
            circle(&mut s, x, y, rng.f(1.6, 3.2), &format!("fill: rgb(\"{small}\")"));
        }
    }
    s
}

fn radar(seed: u64, accent: &str) -> String {
    let mut rng = Rng::new(seed);
    let mut s = String::new();
    let ring = alpha(accent, 0x26);
    let axis = alpha(accent, 0x1a);
    let blip = alpha(accent, 0x6e);
    let cx = rng.f(W * 0.45, W * 0.7);
    let cy = rng.f(H * 0.28, H * 0.45);
    for i in 1..=5 {
        circle(&mut s, cx, cy, i as f64 * 62.0, &format!("stroke: 0.8pt + rgb(\"{ring}\")"));
    }
    let r_max = 320.0;
    for k in 0..6 {
        let ang = k as f64 * std::f64::consts::PI / 6.0;
        let (dx, dy) = (ang.cos() * r_max, ang.sin() * r_max);
        line(&mut s, cx - dx, cy - dy, cx + dx, cy + dy, 0.6, &axis);
    }
    for _ in 0..14 {
        let ang = rng.f(0.0, std::f64::consts::TAU);
        let r = rng.f(30.0, 300.0);
        let (bx, by) = (cx + ang.cos() * r, cy + ang.sin() * r);
        if bx > 8.0 && bx < W - 8.0 && by > 8.0 && by < H - 8.0 {
            circle(&mut s, bx, by, rng.f(2.0, 3.6), &format!("fill: rgb(\"{blip}\")"));
        }
    }
    s
}

fn binary(seed: u64, accent: &str, mono_font: &str) -> String {
    let mut rng = Rng::new(seed);
    let mut s = String::new();
    for _ in 0..15 {
        let x = rng.f(0.0, W - 10.0);
        let y = rng.f(-30.0, H * 0.55);
        let n = 8 + (rng.next() % 14) as usize;
        let shade = if rng.chance(0.3) { 0x3a } else { 0x20 };
        let color = alpha(accent, shade);
        let mut body = String::new();
        for k in 0..n {
            if k > 0 {
                body.push_str("\\ ");
            }
            body.push(if rng.chance(0.5) { '0' } else { '1' });
        }
        let _ = writeln!(
            s,
            "#place(top + left, dx: {x:.1}pt, dy: {y:.1}pt, text(font: \"{mono_font}\", size: 8pt, fill: rgb(\"{color}\"))[{body}])"
        );
    }
    s
}

fn contours(seed: u64, accent: &str) -> String {
    let mut rng = Rng::new(seed);
    let mut s = String::new();
    let stroke = alpha(accent, 0x22);
    let segments = 22;
    let step = W / segments as f64;
    for c in 0..8 {
        let base = 60.0 + c as f64 * 85.0 + rng.f(-18.0, 18.0);
        let mut y = base;
        let mut x = 0.0;
        for _ in 0..segments {
            let ny = (y + rng.f(-16.0, 16.0)).clamp(base - 42.0, base + 42.0);
            line(&mut s, x, y, x + step, ny, 0.8, &stroke);
            x += step;
            y = ny;
        }
    }
    s
}
