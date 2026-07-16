const BASE = import.meta.env?.VITE_API ?? "/api";
export async function listTargets() {
    const r = await fetch(`${BASE}/targets`);
    return r.json();
}
export async function startSweep(repo) {
    const r = await fetch(`${BASE}/sweeps`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo, surfaces: ["code"] }),
    });
    if (!r.ok)
        throw new Error(`start_sweep failed: ${r.status}`);
    return r.json();
}
export async function getSweep(id) {
    const r = await fetch(`${BASE}/sweeps/${id}`);
    return r.json();
}
export async function getFindings(id) {
    const r = await fetch(`${BASE}/sweeps/${id}/findings`);
    if (!r.ok)
        return [];
    return r.json();
}
export async function getAttestation(id) {
    const r = await fetch(`${BASE}/attestations/${id}`);
    return r.json();
}
export function openSweepStream(id, onEvent) {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const host = window.location.host;
    const path = BASE.startsWith("/") ? BASE : "";
    const ws = new WebSocket(`${scheme}://${host}${path}/ws/sweeps/${id}`);
    ws.onmessage = (msg) => {
        try {
            onEvent(JSON.parse(msg.data));
        }
        catch {
            /* ignore */
        }
    };
    return ws;
}
