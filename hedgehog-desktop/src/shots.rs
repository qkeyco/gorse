// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Development builds only: with `GORSE_SHOT_DIR` set, the window takes
//! screenshots of itself (Fast Scan, Deep Scan places, and, with
//! `GORSE_SHOT_FOLDER`, a Deep Scan of that folder while it runs and when it
//! is done; with `GORSE_SHOT_STOP` it is stopped first), writes them as
//! PPM files and closes. Compiled out of release
//! builds.

use crate::{App, Mode};
use eframe::egui;
use std::path::PathBuf;

pub struct Shots {
    dir: PathBuf,
    folder: Option<PathBuf>,
    step: usize,
    frames: u64,
    waiting: bool,
}

impl Shots {
    pub fn from_env() -> Option<Self> {
        let dir = PathBuf::from(std::env::var_os("GORSE_SHOT_DIR")?);
        let _ = std::fs::create_dir_all(&dir);
        Some(Self {
            dir,
            folder: std::env::var_os("GORSE_SHOT_FOLDER").map(PathBuf::from),
            step: 0,
            frames: 0,
            waiting: false,
        })
    }
}

fn save_ppm(path: &std::path::Path, image: &egui::ColorImage) {
    let [w, h] = image.size;
    let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
    for p in &image.pixels {
        out.extend_from_slice(&[p.r(), p.g(), p.b()]);
    }
    let _ = std::fs::write(path, out);
}

impl App {
    pub(crate) fn drive_shots(&mut self, ctx: &egui::Context) {
        let Some(mut s) = self.shots.take() else {
            return;
        };
        s.frames += 1;
        ctx.request_repaint();
        let names = ["fast", "deep-places", "deep-running", "deep-done"];
        if s.waiting {
            let image = ctx.input(|i| {
                i.raw.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = image {
                save_ppm(&s.dir.join(format!("{}.ppm", names[s.step])), &image);
                s.waiting = false;
                s.step += 1;
                s.frames = 0;
            }
            self.shots = Some(s);
            return;
        }
        let ready = match s.step {
            0 => s.frames > 90 && self.running.is_none() && self.license_rx.is_none(),
            1 => {
                self.mode = Mode::Files;
                s.frames > 30
            }
            2 => {
                let Some(folder) = s.folder.clone() else {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    return;
                };
                if s.frames == 1 {
                    self.deep.folders = vec![folder];
                    let plan = self.deep.plan();
                    self.deep.run(plan);
                }
                s.frames > 60
            }
            3 => {
                if s.frames == 1 && std::env::var_os("GORSE_SHOT_STOP").is_some() {
                    self.deep.stop();
                }
                s.frames > 10 && !self.deep.is_scanning()
            }
            _ => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
        };
        if ready {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            s.waiting = true;
        }
        self.shots = Some(s);
    }
}
