import { useEffect, useState } from "react";
import type { ConfigView } from "../types";
import { api } from "../api";
import { ScopeEditor } from "./ScopeEditor";
import { MatchReplaceEditor } from "./MatchReplaceEditor";

export function Settings(props: { config?: ConfigView; onSaved: (c: ConfigView) => void; onImported?: () => void }) {
  const [listen, setListen] = useState("127.0.0.1:8080");
  const [insecure, setInsecure] = useState(false);
  const [passthrough, setPassthrough] = useState("");
  const [dropOutOfScope, setDropOutOfScope] = useState(false);
  const [chromiumPath, setChromiumPath] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [msg, setMsg] = useState("");
  const [importPath, setImportPath] = useState("");
  const [importing, setImporting] = useState(false);
  const [importMsg, setImportMsg] = useState("");

  useEffect(() => {
    if (props.config) {
      setListen(props.config.listen);
      setInsecure(props.config.insecure_upstream);
      setPassthrough(props.config.passthrough_hosts.join("\n"));
      setDropOutOfScope(props.config.drop_out_of_scope);
      setChromiumPath(props.config.chromium_path ?? "");
      setGithubToken(props.config.github_token ?? "");
    }
  }, [props.config]);

  async function save() {
    if (!props.config) return;
    setMsg("");
    try {
      const next: ConfigView = {
        ...props.config,
        listen,
        insecure_upstream: insecure,
        passthrough_hosts: passthrough.split(/\s+/).map((s) => s.trim()).filter(Boolean),
        drop_out_of_scope: dropOutOfScope,
        chromium_path: chromiumPath.trim(),
        github_token: githubToken.trim(),
      };
      const saved = await api.configSet(next);
      props.onSaved(saved);
      setMsg("Saved. The proxy was restarted if it was running.");
    } catch (e) { setMsg(String(e)); }
  }

  async function runImport() {
    const p = importPath.trim();
    if (!p) { setImportMsg("enter the path to an XML item export"); return; }
    setImporting(true); setImportMsg("");
    try {
      const n = await api.importTraffic(p);
      setImportMsg(`Imported ${n} request${n === 1 ? "" : "s"} into history.`);
      setImportPath("");
      props.onImported?.();
    } catch (e) { setImportMsg(String(e)); }
    finally { setImporting(false); }
  }

  return (
    <div className="settings">
      <h2>Proxy settings</h2>
      <label>Listen address
        <input value={listen} onChange={(e) => setListen(e.target.value)} />
      </label>
      <label className="row">
        <input type="checkbox" checked={insecure} onChange={(e) => setInsecure(e.target.checked)} />
        Accept invalid upstream certificates (lab targets only)
      </label>
      <label>Passthrough hosts (one per line; a leading dot matches subdomains)
        <textarea rows={5} value={passthrough} onChange={(e) => setPassthrough(e.target.value)} />
      </label>
      <label className="row">
        <input type="checkbox" checked={dropOutOfScope} onChange={(e) => setDropOutOfScope(e.target.checked)} />
        Refuse out-of-scope requests at the proxy (403). Enforced in the Rust core. Needs scope rules below — with none, everything is refused.
      </label>
      <label>Integrated browser — Chromium path (optional)
        <input value={chromiumPath} placeholder="leave blank to use the bundled / system Chromium"
          onChange={(e) => setChromiumPath(e.target.value)} />
      </label>
      <label>GitHub token for the BApp Store (optional)
        <input type="password" value={githubToken} placeholder="lifts GitHub's 60-requests/hour limit when browsing/installing"
          onChange={(e) => setGithubToken(e.target.value)} />
      </label>
      <div className="row">
        <button className="btn start" onClick={save}>Save</button>
        {msg && <span className="msg">{msg}</span>}
      </div>
      <p className="mut">Data directory: {props.config?.data_dir}</p>

      <hr className="sep" />
      <h2>Import traffic</h2>
      <p className="mut">
        Import an <b>XML item export</b> from another proxy tool into history (its "Save selected
        items" / export-history feature). Other tools' binary project files aren't supported — export items as XML first.
      </p>
      <div className="bapp-import">
        <input placeholder="/path/to/items-export.xml" value={importPath}
          onChange={(e) => setImportPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runImport()} />
        <button className="btn start" disabled={importing} onClick={runImport}>{importing ? "Importing…" : "Import"}</button>
      </div>
      {importMsg && <div className="msg">{importMsg}</div>}

      <hr className="sep" />
      <ScopeEditor />
      <hr className="sep" />
      <MatchReplaceEditor />
    </div>
  );
}
