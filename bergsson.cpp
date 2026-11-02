// bergsson.cpp - Bergsson Mod Scanner: Dear ImGui (DirectX 11) front end + CLI entry point
//
// Build:  build.bat   (MSVC x64; Dear ImGui v1.91.8 lives in third_party/imgui)
//
// Usage:
//   BergssonModScanner.exe                        opens the app
//   BergssonModScanner.exe [paths...] [options]   command-line mode (--help for options)
//
// The scanning engine (zip/class parsing, signatures, behavior analysis, Modrinth, game detection)
// is in scanner_core.h.

#define IMGUI_DEFINE_MATH_OPERATORS
#include "scanner_core.h"

#include <d3d11.h>
#include <windowsx.h>
#include <unordered_map>

#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

// Segoe Fluent Icons / Segoe MDL2 Assets code points (used sparingly)
#define ICON_SEARCH   u8""
#define ICON_CHECK    u8""
#define ICON_WARNING  u8""
#define ICON_CLOSE    u8""
#define ICON_MINIMIZE u8""
#define ICON_MAXIMIZE u8""
#define ICON_RESTORE  u8""
#define ICON_OPEN     u8""
#define ALL_ICONS ICON_SEARCH ICON_CHECK ICON_WARNING ICON_CLOSE ICON_MINIMIZE ICON_MAXIMIZE ICON_RESTORE ICON_OPEN

namespace app {

// ===========================================================================
// Look & feel: neutral surfaces, one accent, color only where it means something
// ===========================================================================

constexpr ImU32 C_BG = IM_COL32(13, 14, 17, 255);
constexpr ImU32 C_PANEL = IM_COL32(19, 21, 25, 255);
constexpr ImU32 C_RAISED = IM_COL32(26, 28, 33, 255);
constexpr ImU32 C_LINE = IM_COL32(255, 255, 255, 16);
constexpr ImU32 C_WHITE = IM_COL32(255, 255, 255, 255);
constexpr ImU32 C_BLACK = IM_COL32(0, 0, 0, 255);
constexpr ImU32 C_TEXT = IM_COL32(234, 236, 240, 255);
constexpr ImU32 C_DIM = IM_COL32(150, 155, 165, 255);
constexpr ImU32 C_FAINT = IM_COL32(106, 111, 122, 255);
constexpr ImU32 C_ACCENT = IM_COL32(124, 160, 255, 255);
constexpr ImU32 C_GREEN = IM_COL32(76, 195, 120, 255);
constexpr ImU32 C_RED = IM_COL32(235, 87, 87, 255);
constexpr ImU32 C_VIOLET = IM_COL32(152, 132, 245, 255);
constexpr ImU32 C_AMBER = IM_COL32(242, 168, 59, 255);
constexpr ImU32 C_CYAN = IM_COL32(86, 196, 232, 255);

const char* kVersion = "3.1";
const float kUiScale = 1.1f;  // overall UI size on top of the monitor's DPI scaling

float g_s = 1.f;
float S(float v) { return v * g_s; }

HWND g_hwnd = nullptr;
float g_titleH = 0, g_capBtnW = 0;
double g_now = 0;

ImFont *fBody, *fSemi, *fSmall, *fLabel, *fH1, *fH2, *fDisplay, *fMono;
ImVector<ImWchar> g_textRanges, g_iconRanges;

ImU32 Alpha(ImU32 c, float a) {
    float base = float((c >> IM_COL32_A_SHIFT) & 0xFF);
    ImU32 al = ImU32(ImClamp(base * a, 0.f, 255.f));
    return (c & ~IM_COL32_A_MASK) | (al << IM_COL32_A_SHIFT);
}

ImU32 Mix(ImU32 a, ImU32 b, float t) {
    t = ImClamp(t, 0.f, 1.f);
    auto ch = [&](int sh) {
        float x = float((a >> sh) & 0xFF), y = float((b >> sh) & 0xFF);
        return ImU32(x + (y - x) * t) << sh;
    };
    return ch(IM_COL32_R_SHIFT) | ch(IM_COL32_G_SHIFT) | ch(IM_COL32_B_SHIFT) | ch(IM_COL32_A_SHIFT);
}

ImVec4 V4(ImU32 c) { return ImGui::ColorConvertU32ToFloat4(c); }
float EaseOut(float t) { t = ImClamp(t, 0.f, 1.f); return 1.f - (1.f - t) * (1.f - t) * (1.f - t); }

// Exponential smoothing toward a target, keyed by id - drives every animation in the app.
std::unordered_map<ImGuiID, float> g_anim;
float Anim(ImGuiID id, float target, float speed = 12.f, float init = NAN) {
    auto it = g_anim.find(id);
    if (it == g_anim.end()) it = g_anim.emplace(id, std::isnan(init) ? target : init).first;
    it->second += (target - it->second) * (1.f - expf(-speed * ImGui::GetIO().DeltaTime));
    return it->second;
}
float Anim(const char* key, float target, float speed = 12.f, float init = NAN) { return Anim(ImHashStr(key), target, speed, init); }
void AnimSet(const char* key, float v) { g_anim[ImHashStr(key)] = v; }

ImVec2 Measure(ImFont* f, const char* t, const char* end = nullptr) { return f->CalcTextSizeA(f->FontSize, FLT_MAX, 0.f, t, end); }
void Text(ImDrawList* dl, ImFont* f, ImVec2 p, ImU32 c, const char* t, const char* end = nullptr) { dl->AddText(f, f->FontSize, p, c, t, end); }
void Text(ImDrawList* dl, ImFont* f, ImVec2 p, ImU32 c, const std::string& t) { Text(dl, f, p, c, t.c_str(), t.c_str() + t.size()); }

// Small-caps style label: letter-spaced, returns the width drawn.
float Label(ImDrawList* dl, ImVec2 p, ImU32 col, const char* text, float spacing = 1.4f) {
    float x = p.x;
    for (int i = 0; text[i]; i++) {
        char ch[2] = {text[i], 0};
        Text(dl, fLabel, ImVec2(x, p.y), col, ch);
        x += Measure(fLabel, ch).x + S(spacing);
    }
    return x - p.x;
}

std::string Ellipsize(ImFont* f, const std::string& s, float maxW) {
    if (maxW <= 0) return "";
    if (Measure(f, s.c_str()).x <= maxW) return s;
    std::string out = s;
    while (!out.empty()) {
        out.pop_back();
        while (!out.empty() && (uint8_t(out.back()) & 0xC0) == 0x80) out.pop_back();  // keep UTF-8 intact
        if (Measure(f, (out + u8"…").c_str()).x <= maxW) return out + u8"…";
    }
    return u8"…";
}

void Glow(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
    for (int i = 5; i >= 1; --i) dl->AddCircleFilled(c, r * (1.f + i * 0.6f), Alpha(col, 0.05f), 24);
}

// ===========================================================================
// Scan state (worker thread publishes, UI copies when the version changes)
// ===========================================================================

struct JarResult {
    fs::path path;
    std::string fileName;
    std::vector<ModReport> reports;
    std::string worst = "QUEUED";
    bool quarantined = false;
};

std::mutex g_mtx;
std::vector<JarResult> g_results;                 // guarded by g_mtx
std::string g_phase, g_currentFile, g_scanError;  // guarded by g_mtx
std::atomic<uint64_t> g_version{1};
std::atomic<bool> g_busy{false}, g_cancel{false}, g_scanDone{false};
std::atomic<int> g_progress{0}, g_progressMax{0};
std::thread g_worker;

std::mutex g_gamesMtx;
std::vector<GameInstance> g_liveGames;  // guarded by g_gamesMtx, refreshed by the poller
std::atomic<bool> g_quit{false};
std::thread g_poller;

void publish(const std::vector<JarResult>& local, size_t i) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (i < g_results.size()) g_results[i] = local[i];
    ++g_version;
}

void setPhase(const std::string& phase, const std::string& file) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_phase = phase;
    g_currentFile = file;
    ++g_version;
}

void scanWorker(std::vector<fs::path> roots, bool online) {
    std::vector<fs::path> jars = collectJars(roots);
    std::vector<JarResult> local(jars.size());
    for (size_t i = 0; i < jars.size(); i++) {
        local[i].path = jars[i];
        local[i].fileName = pathUtf8(jars[i].filename());
    }
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_results = local;
        ++g_version;
    }
    g_progress = 0;
    g_progressMax = int(jars.size()) + (online ? 1 : 0);

    Options opt = makeOptions();
    opt.verbose = true;
    for (size_t i = 0; i < jars.size() && !g_cancel; i++) {
        setPhase("Analyzing", local[i].fileName);
        local[i].worst = "SCANNING";
        publish(local, i);
        scanFile(jars[i], local[i].fileName, opt, local[i].reports);
        local[i].worst = worstVerdict(local[i].reports);
        g_progress = int(i + 1);
        publish(local, i);
    }

    std::string err;
    if (online && !g_cancel && !jars.empty()) {
        setPhase("Verifying with Modrinth", std::to_string(jars.size()) + " files");
        std::vector<ModReport*> tops;
        for (auto& j : local)
            if (!j.reports.empty() && j.reports[0].error.empty()) tops.push_back(&j.reports[0]);
        onlineLookup(tops, err);
        for (size_t i = 0; i < local.size(); i++) {
            if (!local[i].reports.empty()) local[i].worst = worstVerdict(local[i].reports);
            publish(local, i);
        }
        g_progress = g_progressMax.load();
    }
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_scanError = err;
    }
    g_scanDone = true;
}

void gamePoller() {
    while (!g_quit) {
        auto found = findGameProcesses();
        {
            std::lock_guard<std::mutex> lk(g_gamesMtx);
            g_liveGames = std::move(found);
        }
        for (int i = 0; i < 25 && !g_quit; i++) Sleep(100);
    }
}

// ===========================================================================
// UI state
// ===========================================================================

struct Toast { std::string text; ImU32 col; double t0; };

std::vector<JarResult> g_view;
uint64_t g_viewVersion = 0;
std::vector<double> g_appear;  // when each row got its final verdict
std::vector<int> g_feed;       // completion order, for the live feed
std::string g_viewPhase, g_viewFile;
double g_doneAt = -10;

int g_selected = -1;
double g_selectedAt = 0;
int g_filter = 0;  // 0 all, 1 flagged, 2 verified
char g_search[128] = "";
bool g_scrollToSelected = false;
char g_pathBuf[2048] = "";
bool g_pathActive = false, g_searchActive = false;
bool g_online = true;
std::string g_status = "Ready";
std::vector<Toast> g_toasts;
std::vector<GameInstance> g_menuInstances;
bool g_openInstances = false, g_openRowMenu = false, g_openQuarantine = false;
int g_ctxIndex = -1;
std::vector<fs::path> g_pendingDrop;

void PushToast(const std::string& text, ImU32 col) {
    g_toasts.push_back({text, col, g_now});
    if (g_toasts.size() > 3) g_toasts.erase(g_toasts.begin());
}

const char* VerdictWord(const std::string& v) {
    if (v == "MALWARE INDICATORS") return "Malware";
    if (v == "LIKELY CHEAT") return "Cheat";
    if (v == "SUSPICIOUS") return "Suspicious";
    if (v == "OBFUSCATED") return "Obfuscated";
    if (v == "ERROR") return "Unreadable";
    if (v == "OK") return "Clean";
    if (v == "SCANNING") return "Scanning";
    return "Queued";
}

ImU32 VerdictColor(const std::string& v) {
    if (v == "MALWARE INDICATORS") return C_RED;
    if (v == "LIKELY CHEAT") return C_VIOLET;
    if (v == "SUSPICIOUS") return C_AMBER;
    if (v == "OBFUSCATED") return C_CYAN;
    if (v == "ERROR") return C_AMBER;
    if (v == "OK") return C_GREEN;
    if (v == "SCANNING") return C_ACCENT;
    return C_FAINT;
}

ImU32 KindColor(Kind k) {
    switch (k) {
        case Kind::Cheat: return C_VIOLET;
        case Kind::Malware: return C_RED;
        case Kind::Suspicious: return C_AMBER;
        default: return C_CYAN;
    }
}

const char* VerdictExplanation(const std::string& v) {
    if (v == "MALWARE INDICATORS") return "Contains stealer or malware-loader patterns. Do not run this jar.";
    if (v == "LIKELY CHEAT") return "Contains hacked-client code or cheat behavior.";
    if (v == "SUSPICIOUS") return "Some risky patterns - read the evidence before trusting it.";
    if (v == "OBFUSCATED") return "Deliberately obfuscated and not verified on Modrinth or CurseForge.";
    if (v == "ERROR") return "The file could not be read as a jar.";
    if (v == "OK") return "Nothing found that points to cheats, malware or obfuscation.";
    return "Waiting to be scanned.";
}

struct RowInfo {
    int rank = -1, mrState = 0;  // mrState: 0 unknown, 1 verified, 2 impostor, 3 not found
    int cheat = 0, malware = 0, susp = 0, obf = 0;
    float risk = 0;
    std::string mod, source;
};

RowInfo MakeRow(const JarResult& j) {
    RowInfo r;
    r.rank = rankOf(j.worst);
    if (j.reports.empty()) return r;
    const ModReport& t = j.reports[0];
    if (!t.error.empty()) r.mod = t.error;
    else if (!t.modName.empty() || !t.modId.empty())
        r.mod = (t.modName.empty() ? t.modId : t.modName) + (t.modVersion.empty() ? "" : u8"  ·  " + t.modVersion);
    else r.mod = "No mod metadata";
    if (t.mr.matched || t.cfMatched) { r.mrState = 1; r.source = "Verified"; }
    else if (!t.mr.claimedTitle.empty()) { r.mrState = 2; r.source = "Impostor"; }
    else if (t.mr.checked) { r.mrState = 3; r.source = "Unknown origin"; }
    for (const auto& rep : j.reports) {
        r.cheat += rep.score(Kind::Cheat);
        r.malware += rep.score(Kind::Malware);
        r.susp += rep.score(Kind::Suspicious);
        r.obf += rep.score(Kind::Obf);
    }
    if (r.rank > 0) r.risk = ImMin(1.f, (r.malware * 1.2f + r.cheat + r.susp * 0.6f + r.obf * 0.4f) / 120.f);
    return r;
}

// ===========================================================================
// Actions
// ===========================================================================

void StartScan(const std::vector<fs::path>& roots) {
    if (g_busy) return;
    if (g_worker.joinable()) g_worker.join();
    g_cancel = false;
    g_scanDone = false;
    g_busy = true;
    g_selected = -1;
    g_appear.clear();
    g_feed.clear();
    AnimSet("scanPct", 0.f);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_results.clear();
        g_phase = "Collecting jars";
        g_currentFile.clear();
        ++g_version;
    }
    g_status = "Scanning";
    g_worker = std::thread(scanWorker, roots, g_online);
}

std::string Trim(std::string s) {
    while (!s.empty() && (isspace(uint8_t(s.back())) || s.back() == '"')) s.pop_back();
    size_t i = 0;
    while (i < s.size() && (isspace(uint8_t(s[i])) || s[i] == '"')) i++;
    return s.substr(i);
}

void ScanFromPathBox() {
    std::string p = Trim(g_pathBuf);
    if (p.empty()) { PushToast("Choose a mods folder, or start Minecraft and use Detect game", C_AMBER); return; }
    std::error_code ec;
    if (!fs::exists(fs::path(toWide(p)), ec)) { PushToast("That path doesn't exist", C_AMBER); return; }
    StartScan({fs::path(toWide(p))});
}

void SetPath(const fs::path& p) {
    std::string u = pathUtf8(p);
    strncpy_s(g_pathBuf, u.c_str(), _TRUNCATE);
}

void UseInstance(const GameInstance& gi, bool scan) {
    SetPath(gi.modsDir);
    PushToast("Detected " + gi.describe(), C_ACCENT);
    if (scan) StartScan({gi.modsDir});
}

void DetectGame() {
    auto all = findGameProcesses();
    g_menuInstances.clear();
    std::string problem;
    for (auto& gi : all) {
        if (!gi.modsDir.empty()) g_menuInstances.push_back(gi);
        else if (problem.empty()) problem = gi.note;
    }
    if (g_menuInstances.empty()) {
        PushToast(all.empty() ? "No running Minecraft found - start the game and try again" : "Couldn't find a mods folder: " + problem, C_AMBER);
        return;
    }
    if (g_menuInstances.size() == 1) UseInstance(g_menuInstances[0], true);
    else g_openInstances = true;
}

void BrowseFolder() {
    IFileOpenDialog* dlg = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dlg)))) return;
    DWORD opts = 0;
    dlg->GetOptions(&opts);
    dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dlg->SetTitle(L"Choose a Minecraft mods folder");
    if (SUCCEEDED(dlg->Show(g_hwnd))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item))) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                SetPath(path);
                CoTaskMemFree(path);
                ScanFromPathBox();
            }
            item->Release();
        }
    }
    dlg->Release();
}

std::string ReportText(const std::vector<int>& indices) {
    std::ostringstream os;
    std::lock_guard<std::mutex> lk(g_mtx);
    for (int i : indices) {
        if (i < 0 || i >= int(g_results.size())) continue;
        for (const auto& r : g_results[i].reports) {
            ModReport copy = r;
            if (copy.depth == 0) copy.label = pathUtf8(g_results[i].path);
            printReport(os, copy, true, kNoColors);
        }
    }
    return os.str();
}

void ExportReport() {
    if (g_view.empty()) { PushToast("Nothing to export yet", C_AMBER); return; }
    wchar_t file[MAX_PATH] = L"bergsson-report.txt";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Text report (*.txt)\0*.txt\0All files\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    std::vector<int> all(g_view.size());
    std::iota(all.begin(), all.end(), 0);
    std::ofstream f(file, std::ios::binary);
    f << "Bergsson Mod Scanner report\n\n" << ReportText(all);
    PushToast(f ? "Report saved" : "Could not write the report", f ? C_GREEN : C_RED);
}

std::string ProjectUrl(const JarResult& j) {
    if (j.reports.empty()) return "";
    const ModReport& t = j.reports[0];
    if (t.mr.matched && !t.mr.slug.empty()) return "https://modrinth.com/mod/" + t.mr.slug;
    if (!t.mr.claimedSlug.empty()) return "https://modrinth.com/mod/" + t.mr.claimedSlug;
    if (t.cfMatched) return t.cfUrl;
    return "";
}

void OpenUrl(const std::string& url) {
    if (!url.empty()) ShellExecuteW(nullptr, L"open", toWide(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void ShowInExplorer(const fs::path& p) {
    std::wstring args = L"/select,\"" + p.wstring() + L"\"";
    ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
}

// Moves a jar out of the mods folder (renamed so no launcher loads it). Reversible: nothing is deleted.
void Quarantine(int idx) {
    fs::path src;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (idx < 0 || idx >= int(g_results.size()) || g_results[idx].quarantined) return;
        src = g_results[idx].path;
    }
    const wchar_t* local = _wgetenv(L"LOCALAPPDATA");
    fs::path dir = fs::path(local ? local : L".") / L"Bergsson" / L"Quarantine";
    std::error_code ec;
    fs::create_directories(dir, ec);
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t stamp[32];
    swprintf_s(stamp, L"%04d%02d%02d-%02d%02d%02d", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    fs::path dest = dir / (src.filename().wstring() + L"." + stamp + L".quarantined");
    if (!MoveFileExW(src.c_str(), dest.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        PushToast("Quarantine failed - is the game still holding the file open?", C_RED);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_results[idx].path = dest;
        g_results[idx].quarantined = true;
        ++g_version;
    }
    PushToast("Moved to quarantine", C_AMBER);
}

// ===========================================================================
// Widgets
// ===========================================================================

enum class Btn { Primary, Ghost, Danger, Link };

bool Button(const char* id, const char* label, ImVec2 size, Btn style, bool enabled = true, ImU32 linkColor = C_DIM) {
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool pressed = ImGui::InvisibleButton("##b", size) && enabled;
    bool hov = ImGui::IsItemHovered() && enabled;
    if (hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    float h = Anim(ImGui::GetID("h"), hov ? 1.f : 0.f, 16.f);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 b = p + size;
    float r = S(6);
    ImU32 fg = C_TEXT;
    ImFont* f = fSemi;
    switch (style) {
        case Btn::Primary:
            dl->AddRectFilled(p, b, Mix(C_ACCENT, C_WHITE, 0.12f * h), r);
            fg = IM_COL32(12, 16, 30, 255);
            break;
        case Btn::Ghost:
            dl->AddRectFilled(p, b, Mix(C_RAISED, IM_COL32(40, 43, 51, 255), h), r);
            dl->AddRect(p, b, C_LINE, r);
            break;
        case Btn::Danger:
            dl->AddRectFilled(p, b, Alpha(C_RED, 0.12f + 0.10f * h), r);
            dl->AddRect(p, b, Alpha(C_RED, 0.35f), r);
            fg = Mix(C_RED, C_WHITE, 0.25f);
            break;
        case Btn::Link:
            fg = Mix(linkColor, C_TEXT, h);
            f = fBody;
            break;
    }
    if (!enabled) fg = Alpha(fg, 0.35f);
    ImVec2 ts = Measure(f, label);
    ImVec2 tp = style == Btn::Link ? ImVec2(p.x, p.y + (size.y - ts.y) * 0.5f) : p + (size - ts) * 0.5f;
    Text(dl, f, tp, fg, label);
    if (style == Btn::Link && h > 0.01f) dl->AddLine(ImVec2(tp.x, tp.y + ts.y), ImVec2(tp.x + ts.x * h, tp.y + ts.y), Alpha(fg, 0.5f));
    ImGui::PopID();
    return pressed;
}

float LinkWidth(const char* label) { return Measure(fBody, label).x; }

void Switch(const char* id, bool* v, const char* label, float height, bool enabled) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float lw = Measure(fBody, label).x;
    ImVec2 size(S(30) + S(10) + lw, height);
    if (ImGui::InvisibleButton(id, size) && enabled) *v = !*v;
    bool hov = ImGui::IsItemHovered() && enabled;
    if (hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    float on = Anim(ImHashStr(id), *v ? 1.f : 0.f, 14.f);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float th = S(16), ty = p.y + (height - th) * 0.5f;
    ImVec2 ta(p.x, ty), tb(p.x + S(30), ty + th);
    dl->AddRectFilled(ta, tb, Alpha(Mix(IM_COL32(58, 62, 72, 255), C_ACCENT, on), enabled ? 1.f : 0.4f), th);
    float k = th - S(6);
    dl->AddCircleFilled(ImVec2(ImLerp(ta.x + S(3) + k * 0.5f, tb.x - S(3) - k * 0.5f, on), ty + th * 0.5f), k * 0.5f, C_WHITE, 20);
    Text(dl, fBody, ImVec2(p.x + S(40), p.y + (height - fBody->FontSize) * 0.5f), Mix(C_DIM, C_TEXT, hov ? 1.f : on * 0.6f), label);
}

bool InputField(const char* id, const char* icon, const char* hint, char* buf, size_t bufSize, ImVec2 size, bool* active) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float focus = Anim(id, *active ? 1.f : 0.f, 14.f);
    dl->AddRectFilled(p, p + size, C_RAISED, S(6));
    dl->AddRect(p, p + size, Mix(C_LINE, Alpha(C_ACCENT, 0.8f), focus), S(6));
    float x = p.x + S(12);
    if (icon) {
        Text(dl, fSmall, ImVec2(x, p.y + (size.y - fSmall->FontSize) * 0.5f), Mix(C_FAINT, C_ACCENT, focus), icon);
        x += S(22);
    }
    ImGui::SetCursorScreenPos(ImVec2(x, p.y));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, (size.y - ImGui::GetFontSize()) * 0.5f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, 0);
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, 0);
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, 0);
    ImGui::PushStyleColor(ImGuiCol_TextDisabled, V4(C_FAINT));
    ImGui::SetNextItemWidth(p.x + size.x - x - S(10));
    bool enter = ImGui::InputTextWithHint(id, hint, buf, bufSize, ImGuiInputTextFlags_EnterReturnsTrue);
    *active = ImGui::IsItemActive();
    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar();
    ImGui::SetCursorScreenPos(p + ImVec2(size.x, 0));
    return enter;
}

// Text tabs with an underline that slides to the active one.
void Tabs(const char* id, const std::vector<std::string>& items, int* sel, float height) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float x = p.x, gap = S(20), selX = p.x, selW = 0;
    for (int i = 0; i < int(items.size()); i++) {
        float w = Measure(fSemi, items[i].c_str()).x;
        ImGui::SetCursorScreenPos(ImVec2(x, p.y));
        ImGui::PushID(i);
        if (ImGui::InvisibleButton(id, ImVec2(w, height))) *sel = i;
        bool hov = ImGui::IsItemHovered();
        if (hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        ImGui::PopID();
        Text(dl, fSemi, ImVec2(x, p.y + (height - fSemi->FontSize) * 0.5f - S(1)),
             *sel == i ? C_TEXT : (hov ? Mix(C_DIM, C_TEXT, 0.5f) : C_DIM), items[i]);
        if (*sel == i) { selX = x; selW = w; }
        x += w + gap;
    }
    std::string k(id);
    float ux = Anim((k + "x").c_str(), selX, 16.f), uw = Anim((k + "w").c_str(), selW, 16.f);
    dl->AddRectFilled(ImVec2(ux, p.y + height - S(2)), ImVec2(ux + uw, p.y + height), C_ACCENT, S(1));
    ImGui::SetCursorScreenPos(ImVec2(x, p.y));
}

void Panel(ImDrawList* dl, ImVec2 a, ImVec2 b) {
    dl->AddRectFilled(a, b, C_PANEL, S(8));
    dl->AddRect(a, b, C_LINE, S(8));
}

void VerdictDot(ImDrawList* dl, ImVec2 c, const std::string& verdict, float alpha = 1.f) {
    ImU32 col = Alpha(VerdictColor(verdict), alpha);
    if (verdict == "SCANNING") {
        float a0 = float(g_now) * 6.f;
        dl->PathArcTo(c, S(4.5f), a0, a0 + 4.4f, 16);
        dl->PathStroke(col, 0, S(1.6f));
        return;
    }
    if (verdict == "MALWARE INDICATORS") {
        float ph = fmodf(float(g_now) * 0.8f, 1.f);
        dl->AddCircle(c, S(4) + S(6) * ph, Alpha(col, (1.f - ph) * 0.6f), 20, S(1.2f));
    }
    dl->AddCircleFilled(c, S(4), col, 16);
}

// The mountain mark (Bergsson = "mountain"), drawn as a single stroke.
void Mark(ImDrawList* dl, ImVec2 c, float s, ImU32 col, float thickness) {
    ImVec2 pts[5] = {c + ImVec2(-11, 6) * s, c + ImVec2(-4, -4) * s, c + ImVec2(0, 1) * s, c + ImVec2(5, -7) * s, c + ImVec2(12, 6) * s};
    dl->AddPolyline(pts, 5, col, 0, thickness);
}

// ===========================================================================
// Window chrome
// ===========================================================================

void DrawTitleBar(ImDrawList* dl, ImVec2 size) {
    float h = g_titleH;
    Mark(dl, ImVec2(S(30), h * 0.5f + S(1)), S(1), C_ACCENT, S(1.8f));
    float x = S(52);
    Text(dl, fSemi, ImVec2(x, h * 0.5f - fSemi->FontSize * 0.5f), C_TEXT, "Bergsson");
    x += Measure(fSemi, "Bergsson").x + S(7);
    Text(dl, fBody, ImVec2(x, h * 0.5f - fBody->FontSize * 0.5f), C_DIM, "Mod Scanner");

    float bw = S(46);
    g_capBtnW = bw * 3;
    const char* icons[3] = {ICON_MINIMIZE, IsZoomed(g_hwnd) ? ICON_RESTORE : ICON_MAXIMIZE, ICON_CLOSE};
    for (int i = 0; i < 3; i++) {
        ImVec2 p(size.x - bw * (3 - i), 0);
        ImGui::SetCursorScreenPos(p);
        ImGui::PushID(i);
        bool pressed = ImGui::InvisibleButton("##cap", ImVec2(bw, h));
        float hv = Anim(ImGui::GetID("h"), ImGui::IsItemHovered() ? 1.f : 0.f, 18.f);
        ImGui::PopID();
        dl->AddRectFilled(p, p + ImVec2(bw, h), i == 2 ? Alpha(IM_COL32(232, 17, 35, 255), hv) : Alpha(C_WHITE, 0.07f * hv));
        ImVec2 ts = Measure(fSmall, icons[i]);
        Text(dl, fSmall, p + (ImVec2(bw, h) - ts) * 0.5f, Mix(C_DIM, C_WHITE, hv), icons[i]);
        if (pressed) {
            if (i == 0) ShowWindow(g_hwnd, SW_MINIMIZE);
            else if (i == 1) ShowWindow(g_hwnd, IsZoomed(g_hwnd) ? SW_RESTORE : SW_MAXIMIZE);
            else PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
        }
    }
}

void DrawToolbar(ImDrawList* dl, float y, float width, int liveCount) {
    float pad = S(24), H = S(38), gap = S(10);
    float scanW = S(96), detectW = S(128);
    float switchW = S(40) + Measure(fBody, "Verify with Modrinth").x;
    float pathW = width - pad * 2 - scanW - detectW - switchW - gap * 2 - S(24);
    ImGui::SetCursorScreenPos(ImVec2(pad, y));
    if (InputField("##path", nullptr, u8"Mods folder or .jar — drop files anywhere", g_pathBuf, sizeof g_pathBuf, ImVec2(pathW, H), &g_pathActive) && !g_busy)
        ScanFromPathBox();
    float x = pad + pathW + S(20);
    ImGui::SetCursorScreenPos(ImVec2(x, y));
    Switch("##online", &g_online, "Verify with Modrinth", H, !g_busy);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Checks every file against the files published on Modrinth,\nand diffs impostors against the official version.");
    x += switchW + S(4) + gap;
    ImGui::SetCursorScreenPos(ImVec2(x, y));
    if (Button("detect", "Detect game", ImVec2(detectW, H), Btn::Ghost, !g_busy)) DetectGame();
    if (liveCount > 0) {
        ImVec2 c(x + detectW - S(12), y + S(11));
        float ph = fmodf(float(g_now) * 0.7f, 1.f);
        dl->AddCircle(c, S(3) + S(5) * ph, Alpha(C_GREEN, (1.f - ph) * 0.6f), 16, S(1));
        dl->AddCircleFilled(c, S(3), C_GREEN, 12);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip(liveCount ? "Minecraft is running - scan its mods folder" : "Finds the running game's mods folder");
    x += detectW + gap;
    ImGui::SetCursorScreenPos(ImVec2(x, y));
    if (g_busy) {
        if (Button("scan", "Stop", ImVec2(scanW, H), Btn::Danger)) g_cancel = true;
    } else if (Button("scan", "Scan", ImVec2(scanW, H), Btn::Primary)) {
        ScanFromPathBox();
    }
}

// Hairline progress with a glowing head; fades out when the scan ends.
void DrawProgressLine(ImDrawList* dl, float y, float width) {
    int pm = g_progressMax, pv = g_progress;
    float vis = Anim("progVis", g_busy ? 1.f : 0.f, g_busy ? 10.f : 2.f, 0.f);
    dl->AddLine(ImVec2(0, y), ImVec2(width, y), C_LINE);
    if (vis < 0.01f) return;
    float frac = Anim("prog", pm > 0 ? float(pv) / pm : 0.f, 6.f, 0.f);
    float x = width * frac;
    dl->AddRectFilledMultiColor(ImVec2(0, y - S(1)), ImVec2(x, y + S(1)), Alpha(C_ACCENT, 0.f), Alpha(C_ACCENT, vis),
                                Alpha(C_ACCENT, vis), Alpha(C_ACCENT, 0.f));
    if (g_busy) Glow(dl, ImVec2(x, y), S(3), Alpha(C_ACCENT, vis));
}

void DrawStatusBar(ImDrawList* dl, ImVec2 a, ImVec2 b, const std::vector<GameInstance>& live) {
    dl->AddLine(a, ImVec2(b.x, a.y), C_LINE);
    float cy = (a.y + b.y) * 0.5f;
    Text(dl, fSmall, ImVec2(a.x + S(24), cy - fSmall->FontSize * 0.5f), C_FAINT, Ellipsize(fSmall, g_status, (b.x - a.x) * 0.55f));
    const GameInstance* g = nullptr;
    for (auto& gi : live) if (!gi.modsDir.empty()) { g = &gi; break; }
    std::string game = g ? g->describe() : "No game running";
    ImVec2 gs = Measure(fSmall, game.c_str());
    float gx = b.x - S(24) - gs.x;
    if (g) dl->AddCircleFilled(ImVec2(gx - S(10), cy), S(3), C_GREEN, 12);
    Text(dl, fSmall, ImVec2(gx, cy - gs.y * 0.5f), g ? C_DIM : C_FAINT, game);
}

// ===========================================================================
// Mods list
// ===========================================================================

struct Entry { int idx = -1; std::string header; int count = 0; float y = 0, h = 0; };

struct Composition { int malware = 0, cheat = 0, suspicious = 0, obfuscated = 0, error = 0, clean = 0, pending = 0, verified = 0, total = 0; };

Composition Compose(const std::vector<RowInfo>& rows) {
    Composition c;
    for (size_t i = 0; i < g_view.size(); i++) {
        const std::string& v = g_view[i].worst;
        c.total++;
        if (v == "MALWARE INDICATORS") c.malware++;
        else if (v == "LIKELY CHEAT") c.cheat++;
        else if (v == "SUSPICIOUS") c.suspicious++;
        else if (v == "OBFUSCATED") c.obfuscated++;
        else if (v == "ERROR") c.error++;
        else if (v == "OK") c.clean++;
        else c.pending++;
        if (rows[i].mrState == 1) c.verified++;
    }
    return c;
}

std::vector<Entry> BuildEntries(const std::vector<RowInfo>& rows) {
    std::string q = lower(g_search);
    std::vector<int> picked;
    for (int i = 0; i < int(g_view.size()); i++) {
        const RowInfo& r = rows[i];
        bool pass = g_filter == 0 || (g_filter == 1 && r.rank > 0) || (g_filter == 2 && r.mrState == 1);
        if (pass && !q.empty()) pass = lower(g_view[i].fileName + " " + r.mod).find(q) != std::string::npos;
        if (pass) picked.push_back(i);
    }
    auto severity = [&](int i) { return rows[i].rank * 100000 + rows[i].malware + rows[i].cheat + rows[i].susp + rows[i].obf; };
    auto byName = [&](int a, int b) { return lower(g_view[a].fileName) < lower(g_view[b].fileName); };
    std::vector<Entry> out;
    const float rowH = S(54), headH = S(36);
    float y = 0;
    auto add = [&](int idx) { out.push_back({idx, "", 0, y, rowH}); y += rowH; };
    if (g_busy) {
        for (int i : picked) add(i);  // scan order while running
        return out;
    }
    std::vector<int> attention, clean;
    for (int i : picked) (rows[i].rank > 0 ? attention : clean).push_back(i);
    std::stable_sort(attention.begin(), attention.end(), [&](int a, int b) { return severity(a) != severity(b) ? severity(a) > severity(b) : byName(a, b); });
    std::stable_sort(clean.begin(), clean.end(), byName);
    if (!attention.empty()) { out.push_back({-1, "NEEDS ATTENTION", int(attention.size()), y, headH}); y += headH; }
    for (int i : attention) add(i);
    if (!clean.empty()) {
        out.push_back({-1, attention.empty() ? "ALL CLEAN" : "CLEAN", int(clean.size()), y, headH});
        y += headH;
    }
    for (int i : clean) add(i);
    return out;
}

// Stacked bar of verdicts that grows in after a scan, with a compact legend.
void DrawComposition(ImDrawList* dl, ImVec2 a, float width, const Composition& c) {
    struct Seg { int n; ImU32 col; const char* label; };
    const Seg segs[] = {{c.malware, C_RED, "malware"}, {c.cheat, C_VIOLET, "cheat"}, {c.suspicious, C_AMBER, "suspicious"},
                        {c.obfuscated, C_CYAN, "obfuscated"}, {c.error, C_AMBER, "unreadable"}, {c.clean, C_GREEN, "clean"},
                        {c.pending, IM_COL32(60, 64, 74, 255), "queued"}};
    float h = S(6);
    dl->AddRectFilled(a, a + ImVec2(width, h), Alpha(C_WHITE, 0.05f), h);
    if (c.total > 0) {
        float grow = g_busy ? 1.f : EaseOut(float(g_now - g_doneAt) / 0.9f);
        float x = a.x, gap = S(2);
        dl->PushClipRect(a, a + ImVec2(width * grow, h), true);
        for (const Seg& s : segs) {
            if (!s.n) continue;
            float w = Anim(ImHashStr(s.label), width * s.n / c.total, 10.f, 0.f);
            if (w > gap) dl->AddRectFilled(ImVec2(x, a.y), ImVec2(x + w - gap, a.y + h), s.col, S(3));
            x += w;
        }
        dl->PopClipRect();
    }
    float lx = a.x, ly = a.y + S(14);
    for (const Seg& s : segs) {
        if (!s.n) continue;
        std::string t = std::to_string(s.n) + " " + s.label;
        dl->AddCircleFilled(ImVec2(lx + S(4), ly + fSmall->FontSize * 0.5f + S(1)), S(3), s.col, 12);
        Text(dl, fSmall, ImVec2(lx + S(12), ly), C_DIM, t);
        lx += S(12) + Measure(fSmall, t.c_str()).x + S(16);
    }
    if (c.verified) {
        std::string t = std::to_string(c.verified) + " verified on Modrinth";
        ImVec2 ts = Measure(fSmall, t.c_str());
        float rx = a.x + width - ts.x;
        if (rx > lx) {
            Text(dl, fSmall, ImVec2(rx - S(18), ly), C_GREEN, ICON_CHECK);
            Text(dl, fSmall, ImVec2(rx, ly), C_DIM, t);
        }
    }
}

void DrawRow(ImDrawList* dl, ImVec2 a, float w, const Entry& e, const RowInfo& r) {
    const JarResult& j = g_view[e.idx];
    ImVec2 b = a + ImVec2(w, e.h - S(4));
    ImGui::SetCursorScreenPos(a);
    ImGui::PushID(e.idx);
    ImGui::InvisibleButton("##row", b - a, ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
    bool hov = ImGui::IsItemHovered();
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left) && g_selected != e.idx) { g_selected = e.idx; g_selectedAt = g_now; }
    if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) { g_selected = e.idx; g_ctxIndex = e.idx; g_openRowMenu = true; }
    if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
        std::string url = ProjectUrl(j);
        if (!url.empty()) OpenUrl(url); else ShowInExplorer(j.path);
    }
    float hv = Anim(ImGui::GetID("h"), hov ? 1.f : 0.f, 18.f);
    float riskAnim = Anim(ImGui::GetID("risk"), r.risk, 5.f, 0.f);
    ImGui::PopID();

    float appear = e.idx < int(g_appear.size()) && g_appear[e.idx] > 0 ? EaseOut(float(g_now - g_appear[e.idx]) / 0.4f) : 1.f;
    float al = 0.3f + 0.7f * appear, dy = (1.f - appear) * S(6);
    if (hv > 0.01f && g_selected != e.idx) dl->AddRectFilled(a, b, Alpha(C_WHITE, 0.025f * hv), S(6));
    if (j.worst == "SCANNING") {  // shimmer sweeping across the row being analyzed
        float t = fmodf(float(g_now) * 1.4f, 1.f);
        float sx = a.x + (w + S(240)) * t - S(160);
        dl->PushClipRect(a, b, true);
        dl->AddRectFilledMultiColor(ImVec2(sx, a.y), ImVec2(sx + S(80), b.y), Alpha(C_ACCENT, 0.f), Alpha(C_ACCENT, 0.12f), Alpha(C_ACCENT, 0.12f), Alpha(C_ACCENT, 0.f));
        dl->AddRectFilledMultiColor(ImVec2(sx + S(80), a.y), ImVec2(sx + S(160), b.y), Alpha(C_ACCENT, 0.12f), Alpha(C_ACCENT, 0.f), Alpha(C_ACCENT, 0.f), Alpha(C_ACCENT, 0.12f));
        dl->PopClipRect();
    }

    float cy = (a.y + b.y) * 0.5f + dy;
    VerdictDot(dl, ImVec2(a.x + S(20), cy), j.worst, al);

    float meterW = S(52), meterX1 = b.x - S(16), meterX0 = meterX1 - meterW;
    float rightX = meterX0 - S(20);
    float nameX = a.x + S(38), nameW = rightX - S(110) - nameX;
    std::string name = Ellipsize(fSemi, j.fileName, nameW);
    Text(dl, fSemi, ImVec2(nameX, a.y + S(8) + dy), Alpha(j.quarantined ? C_DIM : C_TEXT, al), name);
    if (j.quarantined) Text(dl, fSmall, ImVec2(nameX + Measure(fSemi, name.c_str()).x + S(8), a.y + S(10) + dy), Alpha(C_AMBER, al), "quarantined");
    Text(dl, fSmall, ImVec2(nameX, a.y + S(29) + dy), Alpha(C_FAINT, al), Ellipsize(fSmall, r.mod, nameW));

    const char* vw = VerdictWord(j.worst);
    ImVec2 vs = Measure(fSmall, vw);
    Text(dl, fSmall, ImVec2(rightX - vs.x, a.y + S(9) + dy), Alpha(r.rank > 0 ? VerdictColor(j.worst) : C_DIM, al), vw);
    if (!r.source.empty()) {
        ImU32 sc = r.mrState == 1 ? C_GREEN : r.mrState == 2 ? C_AMBER : C_FAINT;
        ImVec2 ss = Measure(fSmall, r.source.c_str());
        Text(dl, fSmall, ImVec2(rightX - ss.x, a.y + S(29) + dy), Alpha(sc, al), r.source);
    }

    float my = cy - S(1.5f);
    dl->AddRectFilled(ImVec2(meterX0, my), ImVec2(meterX1, my + S(3)), Alpha(C_WHITE, 0.07f), S(2));
    if (riskAnim > 0.005f)
        dl->AddRectFilled(ImVec2(meterX0, my), ImVec2(meterX0 + meterW * riskAnim, my + S(3)), Alpha(VerdictColor(j.worst), al), S(2));
}

void DrawListPanel(ImDrawList* dl, ImVec2 a, ImVec2 b, const std::vector<RowInfo>& rows, const Composition& comp) {
    Panel(dl, a, b);
    float pad = S(20);
    Text(dl, fH2, a + ImVec2(pad, S(18)), C_TEXT, "Mods");
    if (!g_view.empty()) {
        std::string n = std::to_string(g_view.size());
        Text(dl, fBody, a + ImVec2(pad + Measure(fH2, "Mods").x + S(8), S(20)), C_FAINT, n);
    }
    float searchW = S(200);
    ImGui::SetCursorScreenPos(ImVec2(b.x - pad - searchW, a.y + S(14)));
    InputField("##search", ICON_SEARCH, "Search", g_search, sizeof g_search, ImVec2(searchW, S(32)), &g_searchActive);
    std::vector<std::string> tabs = {"All", "Flagged", "Verified"};
    float tabsW = 0;
    for (auto& t : tabs) tabsW += Measure(fSemi, t.c_str()).x;
    tabsW += S(20) * 2;
    ImGui::SetCursorScreenPos(ImVec2(b.x - pad - searchW - S(28) - tabsW, a.y + S(16)));
    Tabs("filter", tabs, &g_filter, S(28));

    float y = a.y + S(62);
    if (!g_view.empty()) {
        DrawComposition(dl, ImVec2(a.x + pad, y), b.x - a.x - pad * 2, comp);
        y += S(46);
    }
    dl->AddLine(ImVec2(a.x, y), ImVec2(b.x, y), C_LINE);

    ImVec2 ra(a.x + S(8), y + S(6)), rb(b.x - S(8), b.y - S(8));
    if (g_view.empty() && !g_busy) {
        const char* t1 = "No scan yet";
        const char* t2 = "Results appear here, grouped by what needs your attention.";
        ImVec2 c = (ra + rb) * 0.5f;
        Text(dl, fSemi, ImVec2(c.x - Measure(fSemi, t1).x * 0.5f, c.y - S(18)), C_DIM, t1);
        Text(dl, fSmall, ImVec2(c.x - Measure(fSmall, t2).x * 0.5f, c.y + S(6)), C_FAINT, t2);
        return;
    }

    std::vector<Entry> entries = BuildEntries(rows);

    // Keyboard navigation through visible rows
    if (!ImGui::GetIO().WantTextInput) {
        std::vector<int> order;
        for (auto& e : entries) if (e.idx >= 0) order.push_back(e.idx);
        if (!order.empty()) {
            int pos = int(std::find(order.begin(), order.end(), g_selected) - order.begin());
            int next = -1;
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) next = pos >= int(order.size()) ? 0 : ImMin(pos + 1, int(order.size()) - 1);
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) next = pos >= int(order.size()) ? 0 : ImMax(pos - 1, 0);
            if (next >= 0) { g_selected = order[next]; g_selectedAt = g_now; g_scrollToSelected = true; }
        }
    }

    ImGui::SetCursorScreenPos(ra);
    ImGui::BeginChild("rows", rb - ra, ImGuiChildFlags_None, ImGuiWindowFlags_NoBackground);
    ImDrawList* cdl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float total = entries.empty() ? 0.f : entries.back().y + entries.back().h;

    // One highlight that glides to the selected row
    const Entry* sel = nullptr;
    for (auto& e : entries) if (e.idx >= 0 && e.idx == g_selected) sel = &e;
    static int lastSel = -1;
    float selVis = Anim("selVis", sel ? 1.f : 0.f, 14.f, 0.f);
    if (sel) {
        if (lastSel < 0) AnimSet("selY", sel->y);
        float sy = Anim("selY", sel->y, 20.f);
        ImVec2 sa = origin + ImVec2(0, sy), sb = sa + ImVec2(w, sel->h - S(4));
        cdl->AddRectFilled(sa, sb, Alpha(C_ACCENT, 0.09f * selVis), S(6));
        cdl->AddRectFilled(sa + ImVec2(0, S(14)), ImVec2(sa.x + S(2), sb.y - S(14)), Alpha(C_ACCENT, selVis), S(1));
        if (g_scrollToSelected) {
            float vis = ImGui::GetWindowHeight();
            if (sel->y < ImGui::GetScrollY()) ImGui::SetScrollY(sel->y);
            else if (sel->y + sel->h > ImGui::GetScrollY() + vis) ImGui::SetScrollY(sel->y + sel->h - vis);
        }
    }
    g_scrollToSelected = false;
    lastSel = sel ? g_selected : -1;

    for (const Entry& e : entries) {
        ImVec2 ea = origin + ImVec2(0, e.y);
        if (!ImGui::IsRectVisible(ea, ea + ImVec2(w, e.h))) continue;
        if (e.idx < 0) {
            float lw = Label(cdl, ea + ImVec2(S(12), S(14)), C_FAINT, e.header.c_str());
            Text(cdl, fLabel, ea + ImVec2(S(12) + lw + S(6), S(14)), C_FAINT, std::to_string(e.count));
            continue;
        }
        DrawRow(cdl, ea, w, e, rows[e.idx]);
    }
    ImGui::SetCursorScreenPos(origin + ImVec2(0, total));
    ImGui::Dummy(ImVec2(w, S(4)));
    if (entries.empty()) {
        const char* none = "Nothing matches this filter";
        Text(cdl, fBody, origin + ImVec2((w - Measure(fBody, none).x) * 0.5f, S(40)), C_FAINT, none);
    }
    ImGui::EndChild();
}

// ===========================================================================
// Right-hand panel: empty state, live scan, overview, details
// ===========================================================================

void CenterText(ImDrawList* dl, ImFont* f, float cx, float y, ImU32 col, const std::string& t) {
    Text(dl, f, ImVec2(cx - Measure(f, t.c_str()).x * 0.5f, y), col, t);
}

void DrawEmptyState(ImDrawList* dl, ImVec2 a, ImVec2 b) {
    float t = float(g_now);
    ImVec2 c((a.x + b.x) * 0.5f, a.y + (b.y - a.y) * 0.36f);
    // The mark, with three points slowly orbiting it
    Mark(dl, c, S(3.2f), C_ACCENT, S(3));
    for (int i = 0; i < 3; i++) {
        float ang = t * 0.6f + i * IM_PI * 2.f / 3.f;
        ImVec2 p = c + ImVec2(cosf(ang) * S(74), sinf(ang) * S(30));
        float depth = 0.5f + 0.5f * sinf(ang);
        dl->AddCircleFilled(p, S(2.f + 1.5f * depth), Alpha(C_ACCENT, 0.25f + 0.6f * depth), 12);
    }
    for (int i = 0; i <= 64; i++) {  // the orbit itself, as a faint ellipse
        float ang = i / 64.f * IM_PI * 2.f;
        dl->PathLineTo(c + ImVec2(cosf(ang) * S(74), sinf(ang) * S(30)));
    }
    dl->PathStroke(Alpha(C_ACCENT, 0.12f), 0, S(1));

    float y = c.y + S(70);
    CenterText(dl, fH1, c.x, y, C_TEXT, "Scan a mods folder");
    CenterText(dl, fBody, c.x, y + S(38), C_DIM, "Bergsson checks every jar for cheat code, malware and obfuscation,");
    CenterText(dl, fBody, c.x, y + S(60), C_DIM, "and verifies it byte-for-byte against Modrinth.");
    float bw = S(150), bh = S(38), gap = S(10);
    ImGui::SetCursorScreenPos(ImVec2(c.x - bw - gap * 0.5f, y + S(100)));
    if (Button("es_detect", "Detect game", ImVec2(bw, bh), Btn::Primary)) DetectGame();
    ImGui::SetCursorScreenPos(ImVec2(c.x + gap * 0.5f, y + S(100)));
    if (Button("es_browse", "Choose folder", ImVec2(bw, bh), Btn::Ghost)) BrowseFolder();
    CenterText(dl, fSmall, c.x, y + S(156), C_FAINT, "or drop a folder or .jar files anywhere on this window");
}

void DrawScanning(ImDrawList* dl, ImVec2 a, ImVec2 b) {
    float pad = S(28);
    int pm = g_progressMax, pv = g_progress;
    float frac = pm > 0 ? float(pv) / pm : 0.f;
    float shown = Anim("scanPct", frac * 100.f, 5.f, 0.f);
    float y = a.y + S(30);
    Label(dl, ImVec2(a.x + pad, y), C_FAINT, "SCANNING");
    char pct[16];
    snprintf(pct, sizeof pct, "%d", int(shown + 0.5f));
    Text(dl, fDisplay, ImVec2(a.x + pad - S(3), y + S(16)), C_TEXT, pct);
    float px = a.x + pad + Measure(fDisplay, pct).x + S(2);
    Text(dl, fH2, ImVec2(px, y + S(16) + fDisplay->FontSize - fH2->FontSize - S(8)), C_DIM, "%");

    std::string sub = std::to_string(ImMin(pv, int(g_view.size()))) + " of " + std::to_string(g_view.size()) + " mods";
    Text(dl, fBody, ImVec2(a.x + pad, y + S(16) + fDisplay->FontSize + S(4)), C_DIM, sub);
    std::string phase = g_viewPhase.empty() ? "Preparing" : g_viewPhase;
    Text(dl, fSmall, ImVec2(a.x + pad, y + S(16) + fDisplay->FontSize + S(26)), C_FAINT,
         Ellipsize(fSmall, phase + (g_viewFile.empty() ? "" : u8"  ·  " + g_viewFile), b.x - a.x - pad * 2));

    // Live feed of finished jars, newest on top
    float fy = y + S(16) + fDisplay->FontSize + S(66);
    dl->AddLine(ImVec2(a.x + pad, fy), ImVec2(b.x - pad, fy), C_LINE);
    fy += S(16);
    Label(dl, ImVec2(a.x + pad, fy), C_FAINT, "RESULTS AS THEY COME IN");
    fy += S(26);
    float rowH = S(30);
    int shownRows = int((b.y - fy - S(16)) / rowH);
    for (int k = 0; k < shownRows && k < int(g_feed.size()); k++) {
        int idx = g_feed[g_feed.size() - 1 - k];
        if (idx >= int(g_view.size())) continue;
        const JarResult& j = g_view[idx];
        float e = idx < int(g_appear.size()) ? EaseOut(float(g_now - g_appear[idx]) / 0.35f) : 1.f;
        float ry = fy + k * rowH - (1.f - e) * S(8);
        float fade = e * (1.f - ImMax(0.f, float(k - shownRows + 3)) / 3.f);
        VerdictDot(dl, ImVec2(a.x + pad + S(4), ry + rowH * 0.5f), j.worst, fade);
        const char* vw = VerdictWord(j.worst);
        ImVec2 vs = Measure(fSmall, vw);
        Text(dl, fBody, ImVec2(a.x + pad + S(18), ry + (rowH - fBody->FontSize) * 0.5f), Alpha(C_TEXT, fade),
             Ellipsize(fBody, j.fileName, b.x - a.x - pad * 2 - S(40) - vs.x));
        Text(dl, fSmall, ImVec2(b.x - pad - vs.x, ry + (rowH - fSmall->FontSize) * 0.5f),
             Alpha(rankOf(j.worst) > 0 ? VerdictColor(j.worst) : C_FAINT, fade), vw);
    }
}

struct TopFinding { int idx; Kind kind; int weight; std::string text; };

void DrawOverview(ImDrawList* dl, ImVec2 a, ImVec2 b, const Composition& c) {
    float pad = S(28);
    float y = a.y + S(30);
    Label(dl, ImVec2(a.x + pad, y), C_FAINT, "OVERVIEW");

    // Donut that sweeps in after the scan
    ImVec2 dc(a.x + pad + S(70), y + S(100));
    float R = S(62), thick = S(9);
    float sweep = EaseOut(float(g_now - g_doneAt) / 1.3f);
    dl->PathArcTo(dc, R, 0, IM_PI * 2, 96);
    dl->PathStroke(Alpha(C_WHITE, 0.05f), ImDrawFlags_Closed, thick);
    struct Seg { int n; ImU32 col; };
    const Seg segs[] = {{c.malware, C_RED}, {c.cheat, C_VIOLET}, {c.suspicious, C_AMBER}, {c.obfuscated, C_CYAN}, {c.error, C_AMBER}, {c.clean, C_GREEN}};
    float start = -IM_PI * 0.5f, total = IM_PI * 2.f * sweep, gapA = c.total > 1 ? 0.03f : 0.f;
    for (const Seg& s : segs) {
        if (!s.n || c.total == 0) continue;
        float span = total * s.n / c.total;
        if (span > gapA * 2) {
            dl->PathArcTo(dc, R, start + gapA, start + span - gapA, ImMax(4, int(span * 20)));
            dl->PathStroke(s.col, 0, thick);
        }
        start += span;
    }
    int flagged = c.malware + c.cheat + c.suspicious + c.obfuscated + c.error;
    std::string big = std::to_string(int(roundf(Anim("ovFlagged", float(flagged), 4.f, 0.f))));
    CenterText(dl, fDisplay, dc.x, dc.y - fDisplay->FontSize * 0.62f, flagged ? C_TEXT : C_GREEN, big);
    CenterText(dl, fSmall, dc.x, dc.y + S(16), C_DIM, flagged == 1 ? "needs attention" : "need attention");

    // Key numbers beside the donut
    float kx = dc.x + R + S(40), ky = dc.y - S(48);
    auto kv = [&](const std::string& v, const char* label, ImU32 col) {
        Text(dl, fH2, ImVec2(kx, ky), col, v);
        Text(dl, fBody, ImVec2(kx + S(44), ky + S(1)), C_DIM, label);
        ky += S(32);
    };
    kv(std::to_string(c.total), "mods scanned", C_TEXT);
    kv(std::to_string(c.verified), "verified on Modrinth", c.verified ? C_GREEN : C_TEXT);
    kv(std::to_string(c.malware + c.cheat), "malware or cheats", c.malware + c.cheat ? C_RED : C_TEXT);

    // Most serious findings across all mods - click to jump to the mod
    std::vector<TopFinding> top;
    for (int i = 0; i < int(g_view.size()); i++)
        for (const auto& r : g_view[i].reports)
            for (const auto& f : r.findings)
                if (f.weight >= 20 && f.kind != Kind::Obf) top.push_back({i, f.kind, f.weight, f.text});
    std::stable_sort(top.begin(), top.end(), [](const TopFinding& x, const TopFinding& y) { return x.weight > y.weight; });

    float ly = dc.y + R + S(44);
    dl->AddLine(ImVec2(a.x + pad, ly), ImVec2(b.x - pad, ly), C_LINE);
    ly += S(16);
    Label(dl, ImVec2(a.x + pad, ly), C_FAINT, "MOST SERIOUS FINDINGS");
    ly += S(26);
    if (top.empty()) {
        Text(dl, fBody, ImVec2(a.x + pad, ly), C_DIM, "Nothing serious found.");
        return;
    }
    float rowH = S(48);
    std::set<std::pair<int, std::string>> seen;
    int shown = 0;
    for (const TopFinding& f : top) {
        if (ly + rowH > b.y - S(10) || shown >= 8) break;
        std::string head = f.text.substr(0, f.text.find(" - "));
        if (!seen.insert({f.idx, head}).second) continue;
        shown++;
        ImVec2 ra(a.x + pad - S(8), ly - S(4)), rb(b.x - pad + S(8), ly + rowH - S(8));
        ImGui::SetCursorScreenPos(ra);
        ImGui::PushID(shown);
        if (ImGui::InvisibleButton("##top", rb - ra)) { g_selected = f.idx; g_selectedAt = g_now; g_scrollToSelected = true; }
        bool hov = ImGui::IsItemHovered();
        float hv = Anim(ImGui::GetID("h"), hov ? 1.f : 0.f, 16.f);
        ImGui::PopID();
        if (hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        dl->AddRectFilled(ra, rb, Alpha(C_WHITE, 0.03f * hv), S(6));
        float appear = EaseOut(float(g_now - g_doneAt - 0.5 - shown * 0.08) / 0.4f);
        dl->AddCircleFilled(ImVec2(a.x + pad + S(3), ly + S(9)), S(3), Alpha(KindColor(f.kind), appear), 12);
        Text(dl, fSemi, ImVec2(a.x + pad + S(16), ly), Alpha(C_TEXT, appear), Ellipsize(fSemi, head, b.x - a.x - pad * 2 - S(60)));
        std::string w = "+" + std::to_string(f.weight);
        Text(dl, fSmall, ImVec2(b.x - pad - Measure(fSmall, w.c_str()).x, ly + S(2)), Alpha(KindColor(f.kind), appear), w);
        Text(dl, fSmall, ImVec2(a.x + pad + S(16), ly + S(20)), Alpha(C_FAINT, appear), Ellipsize(fSmall, g_view[f.idx].fileName, b.x - a.x - pad * 2 - S(16)));
        ly += rowH;
    }
}

void ColoredText(ImFont* f, ImU32 col, const std::string& s, bool wrap = true) {
    ImGui::PushFont(f);
    ImGui::PushStyleColor(ImGuiCol_Text, V4(col));
    if (wrap) ImGui::TextWrapped("%s", s.c_str());
    else ImGui::TextUnformatted(s.c_str());
    ImGui::PopStyleColor();
    ImGui::PopFont();
}

void Section(const char* label) {
    ImGui::Dummy(ImVec2(0, S(14)));
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddLine(p, ImVec2(p.x + ImGui::GetContentRegionAvail().x, p.y), C_LINE);
    Label(dl, p + ImVec2(0, S(16)), C_FAINT, label);
    ImGui::Dummy(ImVec2(0, S(16) + fLabel->FontSize + S(10)));
}

void Fact(const char* label, const std::string& value, ImU32 col = C_TEXT, ImFont* f = nullptr) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    Text(ImGui::GetWindowDrawList(), fSmall, p + ImVec2(0, S(1)), C_FAINT, label);
    ImGui::SetCursorScreenPos(p + ImVec2(S(104), 0));
    ImGui::BeginGroup();
    ColoredText(f ? f : fBody, col, value);
    ImGui::EndGroup();
    ImGui::Dummy(ImVec2(0, S(3)));
}

void ThreatBars(const int sc[4], float width, ImGuiID base) {
    static const char* names[4] = {"Cheat", "Malware", "Suspicious", "Obfuscation"};
    static const ImU32 cols[4] = {C_VIOLET, C_RED, C_AMBER, C_CYAN};
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float gap = S(18), w = (width - gap * 3) / 4;
    for (int i = 0; i < 4; i++) {
        float x = p.x + i * (w + gap);
        Text(dl, fSmall, ImVec2(x, p.y), sc[i] ? C_DIM : C_FAINT, names[i]);
        std::string v = std::to_string(sc[i]);
        Text(dl, fSemi, ImVec2(x + w - Measure(fSemi, v.c_str()).x, p.y - S(2)), sc[i] ? cols[i] : C_FAINT, v);
        ImVec2 ta(x, p.y + S(24)), tb(x + w, p.y + S(27));
        dl->AddRectFilled(ta, tb, Alpha(C_WHITE, 0.06f), S(2));
        float fill = Anim(base + i, ImMin(sc[i] / 100.f, 1.f), 5.f, 0.f);
        if (fill > 0.003f) dl->AddRectFilled(ta, ImVec2(ta.x + w * fill, tb.y), cols[i], S(2));
    }
    ImGui::Dummy(ImVec2(width, S(30)));
}

void Evidence(const Finding& f) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImU32 col = KindColor(f.kind);
    std::string w = "+" + std::to_string(f.weight);
    Text(dl, fSemi, p, f.weight < 10 ? Alpha(col, 0.5f) : col, w);
    std::string text = f.text, context;
    size_t cpos = text.find("\n          context: ");
    if (cpos != std::string::npos) { context = text.substr(cpos + 20); text = text.substr(0, cpos); }
    ImGui::SetCursorScreenPos(p + ImVec2(S(44), 0));
    ImGui::BeginGroup();
    ColoredText(fBody, f.weight < 10 ? C_DIM : C_TEXT, text);
    if (!context.empty()) ColoredText(fMono, C_FAINT, context);
    ImGui::EndGroup();
    ImGui::Dummy(ImVec2(0, S(6)));
}

void DrawDetails(ImDrawList* dl, ImVec2 a, ImVec2 b) {
    const JarResult& j = g_view[g_selected];
    const ModReport* top = j.reports.empty() ? nullptr : &j.reports[0];
    float fade = EaseOut(float(g_now - g_selectedAt) / 0.28f);

    ImGui::SetCursorScreenPos(a + ImVec2(S(1), S(1)));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(28), S(26)));
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, fade);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(S(8), S(4)));
    ImGui::BeginChild("details", b - a - ImVec2(S(2), S(2)), ImGuiChildFlags_AlwaysUseWindowPadding, ImGuiWindowFlags_NoBackground);
    ImDrawList* cdl = ImGui::GetWindowDrawList();
    float width = ImGui::GetContentRegionAvail().x;
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (1.f - fade) * S(8));

    // Header
    ColoredText(fH1, C_TEXT, j.fileName);
    ImGui::Dummy(ImVec2(0, S(2)));
    ImVec2 vp = ImGui::GetCursorScreenPos();
    VerdictDot(cdl, vp + ImVec2(S(4), fSemi->FontSize * 0.5f + S(1)), j.worst);
    ImGui::SetCursorScreenPos(vp + ImVec2(S(16), 0));
    ColoredText(fSemi, VerdictColor(j.worst), VerdictWord(j.worst), false);
    ImGui::SameLine(0, S(10));
    ColoredText(fBody, C_DIM, VerdictExplanation(j.worst));

    // Actions
    ImGui::Dummy(ImVec2(0, S(8)));
    std::string url = ProjectUrl(j);
    struct Act { const char* label; bool enabled; ImU32 col; int id; };
    const Act acts[] = {{"Open project", !url.empty(), C_ACCENT, 0}, {"Show in folder", true, C_DIM, 1},
                        {"Copy report", true, C_DIM, 2}, {"Quarantine", !j.quarantined && !g_busy, C_RED, 3}};
    bool first = true;
    for (const Act& act : acts) {
        if (!act.enabled && act.id == 0) continue;
        if (!first) ImGui::SameLine(0, S(22));
        first = false;
        if (Button(act.label, act.label, ImVec2(LinkWidth(act.label), S(22)), Btn::Link, act.enabled, act.col)) {
            if (act.id == 0) OpenUrl(url);
            else if (act.id == 1) ShowInExplorer(j.path);
            else if (act.id == 2) { ImGui::SetClipboardText(ReportText({g_selected}).c_str()); PushToast("Report copied", C_ACCENT); }
            else { g_ctxIndex = g_selected; g_openQuarantine = true; }
        }
    }

    if (top) {
        Section("FILE");
        if (!top->modId.empty() || !top->modName.empty()) {
            Fact("Mod", (top->modName.empty() ? top->modId : top->modName) + (top->modId.empty() ? "" : "  (" + top->modId + ")"));
            if (!top->modVersion.empty()) Fact("Version", top->modVersion + (top->loader.empty() ? "" : u8"  ·  " + top->loader));
        }
        if (!top->error.empty()) Fact("Problem", top->error, C_AMBER);
        if (top->error.empty()) {
            if (top->mr.matched) {
                std::string v = "Verified on Modrinth - " + top->mr.title + " " + top->mr.version;
                if (top->mr.downloads >= 0) v += u8"  ·  " + formatCount(top->mr.downloads) + " downloads";
                Fact("Source", v, C_GREEN);
            } else if (top->cfMatched) {
                Fact("Source", "Verified on CurseForge - " + top->cfName, C_GREEN);
            } else if (!top->mr.claimedTitle.empty()) {
                Fact("Source", "Claims to be " + top->mr.claimedTitle + ", but isn't one of its published files", C_AMBER);
            } else if (top->mr.checked) {
                Fact("Source", "Not published on Modrinth - origin unknown", C_DIM);
            } else {
                Fact("Source", "Not verified (Modrinth check off)", C_FAINT);
            }
            Fact("Contents", std::to_string(top->classCount) + " classes, " + std::to_string(top->entryCount) + " entries" +
                                 (j.reports.size() > 1 ? ", " + std::to_string(j.reports.size() - 1) + " nested jars" : ""), C_DIM);
            ImVec2 hp = ImGui::GetCursorScreenPos();
            Fact("SHA-1", top->sha1, C_DIM, fMono);
            if (ImGui::IsMouseHoveringRect(hp, hp + ImVec2(width, S(20)))) {
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                ImGui::SetTooltip("Click to copy");
                if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) { ImGui::SetClipboardText(top->sha1.c_str()); PushToast("SHA-1 copied", C_ACCENT); }
            }
            Fact("Location", pathUtf8(j.path), C_FAINT, fSmall);
        }

        int sc[4] = {0, 0, 0, 0};
        for (const auto& r : j.reports) {
            sc[0] += r.score(Kind::Cheat); sc[1] += r.score(Kind::Malware); sc[2] += r.score(Kind::Suspicious); sc[3] += r.score(Kind::Obf);
        }
        Section("THREAT PROFILE");
        ThreatBars(sc, width, ImHashStr(j.fileName.c_str()));

        if (top->diff.done) {
            const OriginalDiff& d = top->diff;
            Section("DIFFERENCES FROM THE OFFICIAL FILE");
            if (!d.versionLabel.empty())
                ColoredText(fBody, C_DIM, "Compared with " + d.versionLabel + ":  " + std::to_string(d.added.size()) + " added, " +
                                              std::to_string(d.modified.size()) + " modified, " + std::to_string(d.removed.size()) +
                                              " removed, " + std::to_string(d.unchanged) + " identical");
            if (!d.note.empty()) ColoredText(fBody, C_DIM, d.note);
            ImGui::Dummy(ImVec2(0, S(4)));
            auto list = [&](const char* sign, ImU32 col, const std::vector<std::string>& v) {
                for (size_t i = 0; i < v.size() && i < 8; i++) ColoredText(fMono, col, std::string(sign) + " " + v[i]);
                if (v.size() > 8) ColoredText(fSmall, C_FAINT, "  and " + std::to_string(v.size() - 8) + " more", false);
            };
            list("+", C_RED, d.added);
            list("~", C_AMBER, d.modified);
            list("-", C_FAINT, d.removed);
        }

        size_t nFind = 0;
        for (const auto& r : j.reports) nFind += r.findings.size();
        Section(("EVIDENCE  " + std::to_string(nFind)).c_str());
        if (nFind == 0 && top->error.empty()) ColoredText(fBody, C_DIM, "No findings.");
        for (const ModReport& r : j.reports) {
            if (r.findings.empty() && r.error.empty()) continue;
            if (r.depth > 0) {
                ImGui::Dummy(ImVec2(0, S(6)));
                std::string inner = r.label.substr(r.label.rfind("!/") + 2);
                ColoredText(fSemi, C_TEXT, "Inside " + inner.substr(inner.rfind('/') == std::string::npos ? 0 : inner.rfind('/') + 1), false);
                ImGui::SameLine(0, S(10));
                ColoredText(fSmall, VerdictColor(verdict(r)), VerdictWord(verdict(r)), false);
                ImGui::Dummy(ImVec2(0, S(4)));
                if (!r.error.empty()) ColoredText(fSmall, C_AMBER, r.error);
            }
            std::vector<Finding> fs_ = r.findings;
            std::stable_sort(fs_.begin(), fs_.end(), [](const Finding& x, const Finding& y) { return x.weight > y.weight; });
            for (const Finding& f : fs_) Evidence(f);
        }
        ImGui::Dummy(ImVec2(0, S(12)));
    }
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
}

void DrawRightPanel(ImDrawList* dl, ImVec2 a, ImVec2 b, const Composition& comp) {
    Panel(dl, a, b);
    if (g_busy) DrawScanning(dl, a, b);
    else if (g_view.empty()) DrawEmptyState(dl, a, b);
    else if (g_selected < 0 || g_selected >= int(g_view.size())) DrawOverview(dl, a, b, comp);
    else DrawDetails(dl, a, b);
}

void DrawToasts(ImVec2 display) {
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    const double life = 4.0;
    float y = display.y - S(52);
    for (int i = int(g_toasts.size()) - 1; i >= 0; --i) {
        const Toast& t = g_toasts[i];
        float age = float(g_now - t.t0);
        float in = EaseOut(age / 0.3f), out = age > life - 0.4 ? EaseOut((age - float(life) + 0.4f) / 0.4f) : 0.f;
        float al = in * (1.f - out);
        ImVec2 ts = Measure(fBody, t.text.c_str());
        float w = ts.x + S(44), h = S(38);
        ImVec2 a(display.x * 0.5f - w * 0.5f, y - h + (1.f - in) * S(12)), b = a + ImVec2(w, h);
        for (int k = 4; k >= 1; --k) dl->AddRectFilled(a - ImVec2(k * 3.f, k * 3.f), b + ImVec2(k * 3.f, k * 3.f), Alpha(C_BLACK, 0.06f * al), S(8) + k * 3.f);
        dl->AddRectFilled(a, b, Alpha(IM_COL32(32, 35, 42, 255), al), S(8));
        dl->AddRect(a, b, Alpha(C_LINE, al), S(8));
        dl->AddCircleFilled(ImVec2(a.x + S(18), a.y + h * 0.5f), S(3.5f), Alpha(t.col, al), 12);
        Text(dl, fBody, ImVec2(a.x + S(30), a.y + (h - ts.y) * 0.5f), Alpha(C_TEXT, al), t.text);
        y -= (h + S(8)) * al;
    }
    g_toasts.erase(std::remove_if(g_toasts.begin(), g_toasts.end(), [&](const Toast& t) { return g_now - t.t0 > life; }), g_toasts.end());
}

void DrawPopups() {
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(8), S(8)));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(S(8), S(6)));
    if (g_openRowMenu) { ImGui::OpenPopup("rowctx"); g_openRowMenu = false; }
    if (ImGui::BeginPopup("rowctx")) {
        if (g_ctxIndex >= 0 && g_ctxIndex < int(g_view.size())) {
            const JarResult& j = g_view[g_ctxIndex];
            std::string url = ProjectUrl(j);
            if (ImGui::MenuItem("Open project page", nullptr, false, !url.empty())) OpenUrl(url);
            if (ImGui::MenuItem("Show in folder")) ShowInExplorer(j.path);
            ImGui::Separator();
            if (ImGui::MenuItem("Copy SHA-1", nullptr, false, !j.reports.empty())) ImGui::SetClipboardText(j.reports[0].sha1.c_str());
            if (ImGui::MenuItem("Copy report")) ImGui::SetClipboardText(ReportText({g_ctxIndex}).c_str());
            ImGui::Separator();
            if (ImGui::MenuItem("Quarantine...", nullptr, false, !j.quarantined && !g_busy)) g_openQuarantine = true;
        }
        ImGui::EndPopup();
    }
    if (g_openInstances) { ImGui::OpenPopup("instances"); g_openInstances = false; }
    if (ImGui::BeginPopup("instances")) {
        for (size_t i = 0; i < g_menuInstances.size(); i++) {
            ImGui::PushID(int(i));
            std::string label = g_menuInstances[i].describe() + "\n" + pathUtf8(g_menuInstances[i].modsDir);
            if (ImGui::Selectable(label.c_str())) UseInstance(g_menuInstances[i], true);
            ImGui::PopID();
        }
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(2);

    if (g_openQuarantine) { ImGui::OpenPopup("Quarantine"); g_openQuarantine = false; }
    ImGui::SetNextWindowSize(ImVec2(S(440), 0));
    ImGui::SetNextWindowPos(ImGui::GetIO().DisplaySize * 0.5f, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(26), S(24)));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, S(10));
    if (ImGui::BeginPopupModal("Quarantine", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {
        if (g_ctxIndex >= 0 && g_ctxIndex < int(g_view.size())) {
            ColoredText(fH2, C_TEXT, "Quarantine this file?", false);
            ColoredText(fBody, C_AMBER, g_view[g_ctxIndex].fileName);
            ImGui::Dummy(ImVec2(0, S(6)));
            ColoredText(fBody, C_DIM, "It's moved to %LOCALAPPDATA%\\Bergsson\\Quarantine and renamed so no launcher loads it. "
                                      "Nothing is deleted - move it back to restore it.");
            ImGui::Dummy(ImVec2(0, S(14)));
            float bw = (ImGui::GetContentRegionAvail().x - S(10)) * 0.5f;
            if (Button("q_cancel", "Cancel", ImVec2(bw, S(36)), Btn::Ghost) || ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
            ImGui::SameLine(0, S(10));
            if (Button("q_ok", "Quarantine", ImVec2(bw, S(36)), Btn::Danger)) {
                Quarantine(g_ctxIndex);
                ImGui::CloseCurrentPopup();
            }
        } else {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(2);
}

// ===========================================================================
// Frame
// ===========================================================================

void SyncView() {
    uint64_t v = g_version;
    if (v == g_viewVersion) return;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_view = g_results;
        g_viewPhase = g_phase;
        g_viewFile = g_currentFile;
    }
    g_viewVersion = v;
    if (g_appear.size() != g_view.size()) g_appear.assign(g_view.size(), -1.0);
    for (size_t i = 0; i < g_view.size(); i++)
        if (g_appear[i] < 0 && rankOf(g_view[i].worst) >= 0) {
            g_appear[i] = g_now;
            g_feed.push_back(int(i));
        }
}

void OnScanFinished() {
    if (g_worker.joinable()) g_worker.join();
    g_busy = false;
    g_viewVersion = 0;
    SyncView();
    g_doneAt = g_now;
    std::string err;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        err = g_scanError;
    }
    int total = int(g_view.size()), malware = 0, flagged = 0, verified = 0;
    for (const auto& j : g_view) {
        if (j.worst == "MALWARE INDICATORS") malware++;
        if (rankOf(j.worst) > 0) flagged++;
        if (!j.reports.empty() && j.reports[0].verified) verified++;
    }
    if (total == 0) {
        g_status = "No .jar files found";
        PushToast("No .jar files in that folder", C_AMBER);
    } else if (g_cancel) {
        g_status = "Scan stopped";
        PushToast("Scan stopped", C_AMBER);
    } else {
        g_status = std::to_string(total) + " mods scanned  \xC2\xB7  " + std::to_string(flagged) + " need attention  \xC2\xB7  " +
                   std::to_string(verified) + " verified" + (err.empty() ? "" : "  \xC2\xB7  " + err);
        if (malware) PushToast(std::to_string(malware) + (malware == 1 ? " mod contains" : " mods contain") + " malware", C_RED);
        else if (flagged) PushToast(std::to_string(flagged) + (flagged == 1 ? " mod needs" : " mods need") + " your attention", C_AMBER);
        else PushToast("All " + std::to_string(total) + " mods look clean", C_GREEN);
        if (!err.empty()) PushToast(err, C_AMBER);
    }
}

void Frame() {
    ImGuiIO& io = ImGui::GetIO();
    g_now = ImGui::GetTime();
    if (g_scanDone.exchange(false)) OnScanFinished();
    SyncView();
    if (!g_pendingDrop.empty() && !g_busy) {
        SetPath(g_pendingDrop.size() == 1 ? g_pendingDrop[0] : g_pendingDrop[0].parent_path());
        StartScan(g_pendingDrop);
        g_pendingDrop.clear();
    }
    if (g_busy) g_status = g_viewPhase.empty() ? "Scanning" : g_viewPhase + (g_viewFile.empty() ? "" : "  \xC2\xB7  " + g_viewFile);

    if (!io.WantTextInput) {
        if (ImGui::IsKeyPressed(ImGuiKey_F5) && !g_busy) ScanFromPathBox();
        if (ImGui::IsKeyPressed(ImGuiKey_Escape)) g_selected = -1;
    }
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O) && !g_busy) BrowseFolder();
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_E) && !g_busy) ExportReport();

    std::vector<GameInstance> live;
    {
        std::lock_guard<std::mutex> lk(g_gamesMtx);
        live = g_liveGames;
    }
    int liveCount = 0;
    for (auto& g : live) if (!g.modsDir.empty()) liveCount++;

    std::vector<RowInfo> rows;
    rows.reserve(g_view.size());
    for (const auto& j : g_view) rows.push_back(MakeRow(j));
    Composition comp = Compose(rows);

    ImVec2 ds = io.DisplaySize;
    ImGui::GetBackgroundDrawList()->AddRectFilled(ImVec2(0, 0), ds, C_BG);
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ds);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##root", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBackground |
                                        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus |
                                        ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PopStyleVar();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    g_titleH = S(44);
    DrawTitleBar(dl, ds);
    float y = g_titleH + S(10);
    DrawToolbar(dl, y, ds.x, liveCount);
    y += S(38) + S(16);
    DrawProgressLine(dl, y, ds.x);
    y += S(16);
    float pad = S(24), statusH = S(30);
    float bottom = ds.y - statusH - S(12);
    float split = pad + (ds.x - pad * 2 - S(14)) * 0.56f;
    DrawListPanel(dl, ImVec2(pad, y), ImVec2(split, bottom), rows, comp);
    DrawRightPanel(dl, ImVec2(split + S(14), y), ImVec2(ds.x - pad, bottom), comp);
    DrawStatusBar(dl, ImVec2(0, ds.y - statusH), ds, live);
    DrawPopups();
    ImGui::End();
    DrawToasts(ds);
}

// ===========================================================================
// Fonts & style
// ===========================================================================

void LoadFonts() {
    ImGuiIO& io = ImGui::GetIO();
    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::string fonts = toUtf8(winDir) + "\\Fonts\\";
    auto exists = [&](const char* f) { std::error_code ec; return fs::exists(fs::path(toWide(fonts + f)), ec); };
    std::string iconFile = exists("SegoeIcons.ttf") ? fonts + "SegoeIcons.ttf" : exists("segmdl2.ttf") ? fonts + "segmdl2.ttf" : "";

    ImFontGlyphRangesBuilder tb;
    tb.AddRanges(io.Fonts->GetGlyphRangesDefault());
    tb.AddText(u8"—–…•·“”’↑↓");
    tb.BuildRanges(&g_textRanges);
    ImFontGlyphRangesBuilder ib;
    ib.AddText(ALL_ICONS);
    ib.BuildRanges(&g_iconRanges);

    auto add = [&](const char* file, const char* fallback, float px, bool icons) -> ImFont* {
        ImFontConfig cfg;
        cfg.OversampleH = 3;
        cfg.OversampleV = 2;
        const char* use = exists(file) ? file : (fallback && exists(fallback) ? fallback : nullptr);
        ImFont* f = use ? io.Fonts->AddFontFromFileTTF((fonts + use).c_str(), S(px), &cfg, g_textRanges.Data) : nullptr;
        if (!f) { ImFontConfig d; d.SizePixels = S(px); f = io.Fonts->AddFontDefault(&d); }
        if (icons && !iconFile.empty()) {
            ImFontConfig ic;
            ic.MergeMode = true;
            ic.PixelSnapH = true;
            ic.GlyphOffset = ImVec2(0, S(px) * 0.16f);
            io.Fonts->AddFontFromFileTTF(iconFile.c_str(), S(px) * 0.9f, &ic, g_iconRanges.Data);
        }
        return f;
    };
    fBody = add("segoeui.ttf", nullptr, 14.5f, true);
    fSemi = add("seguisb.ttf", "segoeui.ttf", 14.5f, true);
    fSmall = add("segoeui.ttf", nullptr, 12.5f, true);
    fLabel = add("seguisb.ttf", "segoeui.ttf", 10.5f, false);
    fH1 = add("seguisb.ttf", "segoeui.ttf", 21.f, false);
    fH2 = add("seguisb.ttf", "segoeui.ttf", 16.5f, false);
    fDisplay = add("segoeuil.ttf", "segoeui.ttf", 46.f, false);
    fMono = add("consola.ttf", nullptr, 12.5f, false);
    io.FontDefault = fBody;
}

void ApplyStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = S(10);
    s.ChildRounding = S(6);
    s.FrameRounding = S(6);
    s.PopupRounding = S(8);
    s.ScrollbarRounding = S(6);
    s.GrabRounding = S(6);
    s.ScrollbarSize = S(8);
    s.WindowBorderSize = 0;
    s.PopupBorderSize = 1;
    s.FramePadding = ImVec2(S(10), S(6));
    s.ItemSpacing = ImVec2(S(8), S(6));
    s.WindowPadding = ImVec2(S(12), S(12));
    s.SelectableTextAlign = ImVec2(0, 0.5f);
    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = V4(C_TEXT);
    c[ImGuiCol_TextDisabled] = V4(C_FAINT);
    c[ImGuiCol_WindowBg] = V4(C_PANEL);
    c[ImGuiCol_PopupBg] = V4(IM_COL32(28, 31, 37, 252));
    c[ImGuiCol_Border] = V4(C_LINE);
    c[ImGuiCol_FrameBg] = V4(C_RAISED);
    c[ImGuiCol_FrameBgHovered] = V4(IM_COL32(34, 37, 43, 255));
    c[ImGuiCol_FrameBgActive] = V4(IM_COL32(38, 41, 48, 255));
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = V4(IM_COL32(255, 255, 255, 26));
    c[ImGuiCol_ScrollbarGrabHovered] = V4(IM_COL32(255, 255, 255, 46));
    c[ImGuiCol_ScrollbarGrabActive] = V4(Alpha(C_ACCENT, 0.7f));
    c[ImGuiCol_Header] = V4(Alpha(C_ACCENT, 0.16f));
    c[ImGuiCol_HeaderHovered] = V4(Alpha(C_ACCENT, 0.22f));
    c[ImGuiCol_HeaderActive] = V4(Alpha(C_ACCENT, 0.30f));
    c[ImGuiCol_Separator] = V4(C_LINE);
    c[ImGuiCol_TextSelectedBg] = V4(Alpha(C_ACCENT, 0.35f));
    c[ImGuiCol_ModalWindowDimBg] = V4(IM_COL32(4, 5, 8, 170));
    c[ImGuiCol_NavHighlight] = ImVec4(0, 0, 0, 0);
}

// ===========================================================================
// Win32 / D3D11 plumbing
// ===========================================================================

ID3D11Device* g_device = nullptr;
ID3D11DeviceContext* g_context = nullptr;
IDXGISwapChain* g_swapChain = nullptr;
ID3D11RenderTargetView* g_rtv = nullptr;
UINT g_resizeW = 0, g_resizeH = 0;

void CreateRenderTarget() {
    ID3D11Texture2D* back = nullptr;
    g_swapChain->GetBuffer(0, IID_PPV_ARGS(&back));
    g_device->CreateRenderTargetView(back, nullptr, &g_rtv);
    back->Release();
}

void CleanupRenderTarget() {
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
}

bool CreateDeviceD3D(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate = {60, 1};
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL got;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &sd,
                                               &g_swapChain, &g_device, &got, &g_context);
    if (hr == DXGI_ERROR_UNSUPPORTED)
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &sd,
                                           &g_swapChain, &g_device, &got, &g_context);
    if (FAILED(hr)) return false;
    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_swapChain) g_swapChain->Release();
    if (g_context) g_context->Release();
    if (g_device) g_device->Release();
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (ImGui_ImplWin32_WndProcHandler(h, m, w, l)) return true;
    switch (m) {
        case WM_NCCALCSIZE:
            if (w) {
                // Borderless: the client area is the whole window. When maximized, Windows oversizes the
                // window by the frame thickness, so pull it back in.
                if (IsZoomed(h)) {
                    auto* p = reinterpret_cast<NCCALCSIZE_PARAMS*>(l);
                    UINT dpi = GetDpiForWindow(h);
                    int fx = GetSystemMetricsForDpi(SM_CXFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
                    int fy = GetSystemMetricsForDpi(SM_CYFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
                    p->rgrc[0].left += fx; p->rgrc[0].right -= fx;
                    p->rgrc[0].top += fy; p->rgrc[0].bottom -= fy;
                }
                return 0;
            }
            break;
        case WM_NCACTIVATE:
            return DefWindowProcW(h, m, w, -1);  // don't repaint a (non-existent) frame
        case WM_NCHITTEST: {
            POINT pt{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
            ScreenToClient(h, &pt);
            RECT rc;
            GetClientRect(h, &rc);
            int b = int(S(6));
            if (!IsZoomed(h)) {
                bool L = pt.x < b, R = pt.x >= rc.right - b, T = pt.y < b, B = pt.y >= rc.bottom - b;
                if (T && L) return HTTOPLEFT;
                if (T && R) return HTTOPRIGHT;
                if (B && L) return HTBOTTOMLEFT;
                if (B && R) return HTBOTTOMRIGHT;
                if (L) return HTLEFT;
                if (R) return HTRIGHT;
                if (T) return HTTOP;
                if (B) return HTBOTTOM;
            }
            if (pt.y < g_titleH && pt.x < rc.right - g_capBtnW) return HTCAPTION;
            return HTCLIENT;
        }
        case WM_SIZE:
            if (w != SIZE_MINIMIZED) { g_resizeW = LOWORD(l); g_resizeH = HIWORD(l); }
            return 0;
        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(l);
            mmi->ptMinTrackSize = {LONG(S(1100)), LONG(S(680))};
            return 0;
        }
        case WM_DROPFILES: {
            HDROP drop = HDROP(w);
            UINT n = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
            g_pendingDrop.clear();
            for (UINT i = 0; i < n; i++) {
                wchar_t buf[MAX_PATH * 4];
                DragQueryFileW(drop, i, buf, UINT(std::size(buf)));
                g_pendingDrop.emplace_back(buf);
            }
            DragFinish(drop);
            return 0;
        }
        case WM_SYSCOMMAND:
            if ((w & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_CLOSE:
            if (g_busy) {
                // Network calls can take a while to time out; don't hang the close.
                g_cancel = true;
                g_quit = true;
                TerminateProcess(GetCurrentProcess(), 0);
            }
            DestroyWindow(h);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int Run(HINSTANCE inst) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    g_s = GetDpiForSystem() / 96.f * kUiScale;

    WNDCLASSEXW wc{sizeof wc};
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wc.lpszClassName = L"BergssonModScanner";
    RegisterClassExW(&wc);

    int W = int(S(1440)), H = int(S(900));
    RECT work;
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    W = ImMin(W, int(work.right - work.left) - 40);
    H = ImMin(H, int(work.bottom - work.top) - 40);
    int X = work.left + (work.right - work.left - W) / 2, Y = work.top + (work.bottom - work.top - H) / 2;
    g_hwnd = CreateWindowExW(0, wc.lpszClassName, L"Bergsson Mod Scanner", WS_OVERLAPPEDWINDOW, X, Y, W, H, nullptr, nullptr, inst, nullptr);

    BOOL dark = TRUE;
    DwmSetWindowAttribute(g_hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof dark);
    int corners = 2;  // DWMWCP_ROUND
    DwmSetWindowAttribute(g_hwnd, 33 /*DWMWA_WINDOW_CORNER_PREFERENCE*/, &corners, sizeof corners);
    COLORREF border = RGB(38, 41, 48);
    DwmSetWindowAttribute(g_hwnd, 34 /*DWMWA_BORDER_COLOR*/, &border, sizeof border);
    MARGINS margins{1, 1, 1, 1};
    DwmExtendFrameIntoClientArea(g_hwnd, &margins);
    SetWindowPos(g_hwnd, nullptr, 0, 0, 0, 0, SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER);
    DragAcceptFiles(g_hwnd, TRUE);

    if (!CreateDeviceD3D(g_hwnd)) {
        CleanupDeviceD3D();
        MessageBoxW(nullptr, L"Direct3D 11 is not available on this machine.", L"Bergsson Mod Scanner", MB_ICONERROR);
        return 1;
    }
    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    LoadFonts();
    ApplyStyle();
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);

    // Prefill: a running game wins, otherwise the default .minecraft/mods.
    std::vector<GameInstance> running;
    for (auto& gi : findGameProcesses()) if (!gi.modsDir.empty()) running.push_back(gi);
    std::error_code ec;
    if (running.size() == 1) { SetPath(running[0].modsDir); g_status = "Detected " + running[0].describe(); }
    else if (fs::is_directory(defaultModsDir(), ec)) { SetPath(defaultModsDir()); g_status = "Ready  \xC2\xB7  press Scan or F5"; }
    else g_status = "Ready  \xC2\xB7  start Minecraft and use Detect game";
    g_poller = std::thread(gamePoller);

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;
        if (IsIconic(g_hwnd)) { Sleep(50); continue; }
        if (g_resizeW && g_resizeH) {
            CleanupRenderTarget();
            g_swapChain->ResizeBuffers(0, g_resizeW, g_resizeH, DXGI_FORMAT_UNKNOWN, 0);
            g_resizeW = g_resizeH = 0;
            CreateRenderTarget();
        }
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        Frame();
        ImGui::Render();
        const float clear[4] = {13 / 255.f, 14 / 255.f, 17 / 255.f, 1.f};
        g_context->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_context->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swapChain->Present(1, 0);
    }

    g_quit = true;
    if (g_poller.joinable()) g_poller.join();
    if (g_worker.joinable()) g_worker.join();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(g_hwnd);
    UnregisterClassW(wc.lpszClassName, inst);
    CoUninitialize();
    return 0;
}

}  // namespace app

// ---------------------------------------------------------------------------
// Entry point: no arguments = app, otherwise command-line mode
// ---------------------------------------------------------------------------

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::wstring> args;
    for (int i = 1; argv && i < argc; i++) args.emplace_back(argv[i]);
    if (argv) LocalFree(argv);
    if (args.empty()) return app::Run(inst);

    // Output redirected to a file or pipe: the CRT already writes there.
    HANDLE inherited = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD type = inherited && inherited != INVALID_HANDLE_VALUE ? GetFileType(inherited) : FILE_TYPE_UNKNOWN;
    if (type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE) return cliMain(args, false);

    bool attached = AttachConsole(ATTACH_PARENT_PROCESS) != 0;
    if (!attached) AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    std::cout.clear();
    std::cerr.clear();
    SetConsoleOutputCP(CP_UTF8);
    bool color = false;
    HANDLE out = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD mode = 0;
    if (out != INVALID_HANDLE_VALUE && GetConsoleMode(out, &mode) && SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) color = true;
    std::cout << "\n";
    int rc = cliMain(args, color);
    std::cout.flush();
    if (!attached) { std::cout << "\nPress Enter to close..."; std::cout.flush(); getchar(); }
    return rc;
}
