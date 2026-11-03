#!/usr/bin/env swift
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// dmg-background.swift — Draw the Finder background for Gorse-macOS.dmg.
//
// Usage: swift dmg-background.swift OUTPUT_DIR
//
// Writes background.png (600x400 points at 1x) and background@2x.png
// (1200x800) into OUTPUT_DIR. bundle-desktop.sh folds the pair into a
// multi-representation TIFF with `tiffutil -cathidpicheck` so Finder picks
// the sharp one on Retina displays. Only AppKit and CoreGraphics are used;
// no package, no Homebrew.
//
// The geometry matches the Finder layout in bundle-desktop.sh: a 600x400
// window, 128-point icons centred at (150,190) for the app and (450,190)
// for the Applications shortcut, so the arrow runs between the two icons
// at their mid-height and the caption sits in the band above them, clear
// of the icon labels that Finder draws below.

import AppKit
import CoreGraphics
import Foundation

let width: CGFloat = 600
let height: CGFloat = 400
let appCentre = CGPoint(x: 150, y: 190)
let appsCentre = CGPoint(x: 450, y: 190)
let iconSize: CGFloat = 128

func render(scale: CGFloat, to url: URL) throws {
    let pixelW = Int(width * scale)
    let pixelH = Int(height * scale)
    guard let context = CGContext(
        data: nil, width: pixelW, height: pixelH, bitsPerComponent: 8, bytesPerRow: 0,
        space: CGColorSpace(name: CGColorSpace.sRGB)!,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else { throw NSError(domain: "dmg-background", code: 1, userInfo: [NSLocalizedDescriptionKey: "no CGContext"]) }

    // Work in points with the origin at the top left, as Finder lays icons out.
    context.scaleBy(x: scale, y: scale)
    context.translateBy(x: 0, y: height)
    context.scaleBy(x: 1, y: -1)

    let graphics = NSGraphicsContext(cgContext: context, flipped: true)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = graphics
    defer { NSGraphicsContext.restoreGraphicsState() }

    // Background: a light neutral with a faint vertical gradient, light enough
    // that Finder's dark icon labels stay readable.
    let top = NSColor(srgbRed: 0.973, green: 0.973, blue: 0.980, alpha: 1)
    let bottom = NSColor(srgbRed: 0.918, green: 0.922, blue: 0.937, alpha: 1)
    NSGradient(starting: top, ending: bottom)!
        .draw(in: NSRect(x: 0, y: 0, width: width, height: height), angle: 90)

    // Arrow from the app to the Applications folder, clear of both icons.
    let gap: CGFloat = 34
    let start = CGPoint(x: appCentre.x + iconSize / 2 + gap, y: appCentre.y)
    let end = CGPoint(x: appsCentre.x - iconSize / 2 - gap, y: appsCentre.y)
    let arrowColour = NSColor(srgbRed: 0.55, green: 0.56, blue: 0.60, alpha: 1)
    arrowColour.setStroke()
    arrowColour.setFill()
    let headLength: CGFloat = 22
    let headHalfWidth: CGFloat = 13
    let shaft = NSBezierPath()
    shaft.lineWidth = 6
    shaft.lineCapStyle = .round
    shaft.move(to: start)
    shaft.line(to: CGPoint(x: end.x - headLength + 4, y: end.y))
    shaft.stroke()
    let head = NSBezierPath()
    head.move(to: end)
    head.line(to: CGPoint(x: end.x - headLength, y: end.y - headHalfWidth))
    head.line(to: CGPoint(x: end.x - headLength, y: end.y + headHalfWidth))
    head.close()
    head.fill()

    // Caption in the band above the icons (icon tops are at y = 126).
    let paragraph = NSMutableParagraphStyle()
    paragraph.alignment = .center
    let caption = NSAttributedString(
        string: "Drag Gorse to Applications",
        attributes: [
            .font: NSFont.systemFont(ofSize: 17, weight: .medium),
            .foregroundColor: NSColor(srgbRed: 0.25, green: 0.26, blue: 0.29, alpha: 1),
            .paragraphStyle: paragraph,
        ])
    caption.draw(in: NSRect(x: 0, y: 48, width: width, height: 30))

    guard let image = context.makeImage() else { throw NSError(domain: "dmg-background", code: 2) }
    let rep = NSBitmapImageRep(cgImage: image)
    rep.size = NSSize(width: width, height: height)  // 72 or 144 dpi by scale
    guard let png = rep.representation(using: .png, properties: [:]) else { throw NSError(domain: "dmg-background", code: 3) }
    try png.write(to: url)
}

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write("usage: dmg-background.swift OUTPUT_DIR\n".data(using: .utf8)!)
    exit(2)
}
let outDir = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
do {
    try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
    try render(scale: 1, to: outDir.appendingPathComponent("background.png"))
    try render(scale: 2, to: outDir.appendingPathComponent("background@2x.png"))
} catch {
    FileHandle.standardError.write("dmg-background: \(error)\n".data(using: .utf8)!)
    exit(1)
}
