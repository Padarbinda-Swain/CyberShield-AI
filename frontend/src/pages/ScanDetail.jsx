import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Trash2 } from "lucide-react";
import { api } from "../api.js";
import ResultView from "../components/ResultView.jsx";

export default function ScanDetail() {
  const { id } = useParams(), loc = useLocation(), nav = useNavigate();
  const [r, setR] = useState(loc.state?.result || null), [err, setErr] = useState("");
  useEffect(() => { if (!r || r.id !== id) api(`/scans/${id}`).then(setR).catch((e) => setErr(e.message)); }, [id]);
  const del = async () => { if (confirm("Delete this scan from your history?")) { await api(`/scans/${id}`, { method: "DELETE" }); nav("/history"); } };
  return (
    <>
      <div className="page-h"><Link to="/history" className="btn ghost sm" style={{ paddingLeft: 0 }}><ArrowLeft size={16} />History</Link>
        <div style={{ display: "flex", gap: 8 }}><Link className="btn sm" to="/scan">Scan something else</Link><button className="btn sm ghost" onClick={del}><Trash2 size={15} />Delete</button></div></div>
      {err ? <div className="err">{err}</div> : r ? <ResultView r={r} /> : <div className="empty">Loading result…</div>}
    </>
  );
}
