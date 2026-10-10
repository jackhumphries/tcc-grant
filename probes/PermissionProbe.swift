import AppKit
import AVFoundation
import Contacts
import EventKit
import Photos
import Speech
import IOKit.hid
import ScreenCaptureKit

@main
struct PermissionProbe {
    static func main() async {
        let args = CommandLine.arguments
        var results: [String: Any] = [
            "pid": ProcessInfo.processInfo.processIdentifier,
            "bundle": Bundle.main.bundleIdentifier ?? "standalone",
            "screen-recording": CGPreflightScreenCaptureAccess(),
            "accessibility": AXIsProcessTrusted(),
            "input-monitoring": IOHIDCheckAccess(kIOHIDRequestTypeListenEvent).rawValue == 0,
            "camera": AVCaptureDevice.authorizationStatus(for: .video).rawValue,
            "microphone": AVCaptureDevice.authorizationStatus(for: .audio).rawValue,
            "contacts": CNContactStore.authorizationStatus(for: .contacts).rawValue,
            "calendar": EKEventStore.authorizationStatus(for: .event).rawValue,
            "reminders": EKEventStore.authorizationStatus(for: .reminder).rawValue,
            "photos": PHPhotoLibrary.authorizationStatus(for: .readWrite).rawValue,
            "speech-recognition": SFSpeechRecognizer.authorizationStatus().rawValue,
            "rebuild": "A"
        ]
        if let handle = dlopen("/System/Library/PrivateFrameworks/TCC.framework/TCC", RTLD_NOW),
           let symbol = dlsym(handle, "TCCAccessPreflight") {
            typealias Preflight = @convention(c) (CFString, CFDictionary?) -> Int32
            let preflight = unsafeBitCast(symbol, to: Preflight.self)
            results["full-disk-access-preflight"] = preflight("kTCCServiceSystemPolicyAllFiles" as CFString, nil)
        }
        if args.contains("--capture") && CGPreflightScreenCaptureAccess() {
            do {
                let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
                if let display = content.displays.first {
                    let config = SCStreamConfiguration()
                    config.width = 400
                    config.height = 300
                    let filter = SCContentFilter(display: display, excludingWindows: [])
                    let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: config)
                    results["capture"] = ["width": image.width, "height": image.height]
                } else {
                    results["capture-error"] = "No display is available"
                }
            } catch {
                results["capture-error"] = String(describing: error)
            }
        }
        // Preflight Apple Events: askUserIfNeeded=false guarantees no consent prompt.
        if let i = args.firstIndex(of: "--receiver"), args.count > i + 1 {
            let receiver = args[i + 1]
            let data = receiver.data(using: .utf8)!
            var desc = AEAddressDesc()
            let created = data.withUnsafeBytes { b in
                AECreateDesc(DescType(typeApplicationBundleID), b.baseAddress, data.count, &desc)
            }
            if created == noErr {
                results["automation"] = AEDeterminePermissionToAutomateTarget(&desc,
                    AEEventClass(typeWildCard), AEEventID(typeWildCard), false)
                AEDisposeDesc(&desc)
            }
        }
        if let i = args.firstIndex(of: "--read"), args.count > i + 1 {
            do {
                let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: args[i + 1]))
                defer { try? file.close() }
                let data = try file.read(upToCount: 1) ?? Data()
                results["file-read"] = data.count
            } catch { results["file-error"] = String(describing: error) }
        }
        let data = try! JSONSerialization.data(withJSONObject: results, options: [.prettyPrinted, .sortedKeys])
        if let i = args.firstIndex(of: "--output"), args.count > i + 1 {
            try! data.write(to: URL(fileURLWithPath: args[i + 1]))
        } else {
            print(String(data: data, encoding: .utf8)!)
        }
        if let i = args.firstIndex(of: "--hold"), args.count > i + 1,
           let seconds = UInt64(args[i + 1]) {
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
        }
    }
}
