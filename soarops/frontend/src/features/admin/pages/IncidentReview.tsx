import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiClient } from '../../../api/client';
import type { Packet } from '../../../types';
import { ShieldAlert, Activity, MapPin, Server, User, ArrowLeft, CheckCircle, XCircle } from 'lucide-react';
import clsx from 'clsx';

const IncidentReview = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [incident, setIncident] = useState<Packet | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isResolving, setIsResolving] = useState(false);

    const [statusToast, setStatusToast] = useState<string | null>(null);
    const [remainingCount, setRemainingCount] = useState<number>(0);

    useEffect(() => {
        const fetchIncident = async () => {
            try {
                const res = await apiClient.get('/incidents/pending');
                const list: Packet[] = res.data;
                setRemainingCount(list.length);
                const found = id
                    ? list.find((i: Packet) => i.id === Number(id))
                    : (list.length > 0 ? list[0] : null);
                setIncident(found || null);
            } catch (error) {
                console.error("Failed to fetch incident", error);
            } finally {
                setIsLoading(false);
            }
        };
        fetchIncident();
    }, [id]);

    const handleAction = async (action: 'BLOCK' | 'IGNORE') => {
        if (!incident) return;
        setIsResolving(true);
        const resolvedId = incident.id;
        try {
            await apiClient.post(`/incidents/${resolvedId}/resolve`, { action });

            // Fetch the updated queue
            const res = await apiClient.get('/incidents/pending');
            const remainingList: Packet[] = res.data;
            setRemainingCount(remainingList.length);

            const actionLabel = action === 'BLOCK' ? 'Blocked & Logged' : 'Marked as False Positive';
            setStatusToast(`Incident #${resolvedId} ${actionLabel}`);
            setTimeout(() => setStatusToast(null), 3500);

            if (remainingList.length > 0) {
                // Seamlessly advance to the next pending incident in the queue
                const nextIncident = remainingList[0];
                setIncident(nextIncident);
                navigate(`/admin/incidents/review/${nextIncident.id}`, { replace: true });
            } else {
                setIncident(null);
            }
        } catch (error) {
            console.error("Failed to resolve", error);
        } finally {
            setIsResolving(false);
        }
    };

    if (isLoading) return <div className="p-8 text-center text-slate-500">Loading incident details...</div>;

    if (!incident) {
        return (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center bg-slate-50 dark:bg-[#0b1019] min-h-screen">
                <div className="w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-500 mb-4 shadow-lg">
                    <CheckCircle className="w-8 h-8" />
                </div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Queue Clear!</h2>
                <p className="text-slate-500 dark:text-slate-400 max-w-md mb-6">
                    All pending security incidents have been successfully reviewed and resolved. The automated SOAR engine is continuously monitoring incoming traffic.
                </p>
                <button
                    onClick={() => navigate('/admin/dashboard')}
                    className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg shadow-lg shadow-blue-500/20 transition-all flex items-center gap-2"
                >
                    <ArrowLeft className="w-4 h-4" /> Return to Dashboard
                </button>
            </div>
        );
    }

    return (
        <div className="flex h-full flex-col bg-slate-50 dark:bg-[#0b1019] relative">
            {/* Header */}
            <div className="bg-white dark:bg-[#151b29] border-b border-slate-200 dark:border-slate-800 px-6 py-4 flex items-center justify-between shrink-0">
                <div className="flex items-center gap-4">
                    <button onClick={() => navigate('/admin/dashboard')} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full transition-colors">
                        <ArrowLeft className="w-5 h-5 text-slate-500" />
                    </button>
                    <div>
                        <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                            Incident #{incident.id}
                            <span className={clsx(
                                "text-xs px-2 py-0.5 rounded border uppercase tracking-wider",
                                incident.confidence > 0.9 ? "bg-red-500/10 text-red-500 border-red-500/20" : "bg-amber-500/10 text-amber-500 border-amber-500/20"
                            )}>
                                {incident.confidence > 0.9 ? 'Critical' : 'High Severity'}
                            </span>
                        </h1>
                        <p className="text-sm text-slate-500 dark:text-slate-400">{incident.type}</p>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    {statusToast && (
                        <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-xs font-semibold rounded-full animate-bounce">
                            <CheckCircle className="w-3.5 h-3.5" />
                            {statusToast}
                        </div>
                    )}
                    {remainingCount > 0 && (
                        <span className="text-xs bg-amber-500/10 border border-amber-500/20 text-amber-500 px-2.5 py-1 rounded-full font-semibold">
                            {remainingCount} Pending in Queue
                        </span>
                    )}
                    <div className="text-right hidden sm:block pl-2 border-l border-slate-200 dark:border-slate-800">
                        <p className="text-xs text-slate-500 uppercase font-bold">Time Detected</p>
                        <p className="text-sm font-mono text-slate-700 dark:text-slate-300">{new Date(incident.timestamp).toLocaleString()}</p>
                    </div>
                </div>
            </div>

            <div className="flex-1 overflow-hidden flex flex-col lg:flex-row">
                {/* Left Sidebar: Context */}
                <aside className="w-full lg:w-80 bg-white dark:bg-[#151b29] border-r border-slate-200 dark:border-slate-800 overflow-y-auto p-6 shrink-0 [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-slate-300 dark:[&::-webkit-scrollbar-thumb]:bg-slate-700 [&::-webkit-scrollbar-thumb]:rounded-full">
                    <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-4">Context Data</h3>

                    <div className="space-y-6">
                        {/* Traffic Volume */}
                        <div>
                            <label className="text-xs text-slate-400 block mb-1">Traffic Volume</label>
                            <div className="flex items-center gap-2">
                                <Activity className="w-4 h-4 text-slate-400" />
                                <span className={clsx(
                                    "text-sm font-bold px-2 py-0.5 rounded",
                                    incident.traffic_volume === 'High' ? "bg-red-500/10 text-red-500" :
                                        incident.traffic_volume === 'Medium' ? "bg-amber-500/10 text-amber-500" :
                                            "bg-emerald-500/10 text-emerald-500"
                                )}>
                                    {incident.traffic_volume || 'Normal'}
                                </span>
                            </div>
                        </div>

                        {/* Burst Score */}
                        <div>
                            <label className="text-xs text-slate-400 block mb-1">Burst Score</label>
                            <div className="flex items-center gap-2">
                                <div className="w-full bg-slate-200 dark:bg-slate-700 h-2 rounded-full overflow-hidden flex-1">
                                    <div className={clsx("h-full", (incident.burst_score || 0) > 3 ? "bg-red-500" : (incident.burst_score || 0) > 1.5 ? "bg-amber-500" : "bg-emerald-500")} style={{ width: `${Math.min(((incident.burst_score || 0) / 5) * 100, 100)}%` }}></div>
                                </div>
                                <span className="text-sm font-mono font-bold dark:text-white">{incident.burst_score || 0}</span>
                            </div>
                            <p className="text-[10px] text-slate-500 mt-1">
                                {(incident.burst_score || 0) < 1.5 ? "Normal Behavior" : "Suspicious Spikes Detected"}
                            </p>
                        </div>

                        {/* Failed Attempts */}
                        <div>
                            <label className="text-xs text-slate-400 block mb-1">Failed Attempts</label>
                            <div className="flex items-center justify-between">
                                <span className="text-sm font-mono font-bold dark:text-white">{incident.failed_attempts || 0}</span>
                                <span className={clsx(
                                    "text-[10px] px-1.5 py-0.5 rounded uppercase font-bold",
                                    (incident.failed_attempts || 0) > 20 ? "bg-red-100 text-red-600" :
                                        (incident.failed_attempts || 0) > 5 ? "bg-amber-100 text-amber-600" : "bg-emerald-100 text-emerald-600"
                                )}>
                                    {(incident.failed_attempts || 0) > 20 ? "Critical" : (incident.failed_attempts || 0) > 5 ? "Suspicious" : "Normal"}
                                </span>
                            </div>
                        </div>

                        {/* Login Behavior */}
                        <div>
                            <label className="text-xs text-slate-400 block mb-1">Login Behavior</label>
                            <div className="flex items-center gap-2">
                                <User className="w-4 h-4 text-slate-400" />
                                <span className="text-sm font-medium dark:text-white">{incident.login_behavior || 'Normal'}</span>
                            </div>
                        </div>

                        <hr className="border-slate-100 dark:border-slate-800" />

                        <div>
                            <label className="text-xs text-slate-400 block mb-1">Source IP</label>
                            <div className="flex items-center gap-3">
                                <div className="w-8 h-8 rounded bg-blue-500/10 flex items-center justify-center text-blue-500">
                                    <Server className="w-4 h-4" />
                                </div>
                                <div>
                                    <div className="font-mono text-sm font-bold text-slate-900 dark:text-white">{incident.src_ip}</div>
                                    <div className="text-xs text-slate-500">{incident.country}</div>
                                </div>
                            </div>
                        </div>

                        <div>
                            <label className="text-xs text-slate-400 block mb-1">Target</label>
                            <div className="flex items-center gap-3">
                                <div className="w-8 h-8 rounded bg-purple-500/10 flex items-center justify-center text-purple-500">
                                    <Activity className="w-4 h-4" />
                                </div>
                                <div>
                                    <div className="font-mono text-sm font-bold text-slate-900 dark:text-white">Port {incident.destination_port}</div>
                                    <div className="text-xs text-slate-500">Protocol: TCP</div>
                                </div>
                            </div>
                        </div>

                        {incident.target_username && (
                            <div className="bg-red-50 dark:bg-red-900/10 p-3 rounded border border-red-100 dark:border-red-900/20">
                                <label className="text-xs text-red-500 font-bold block mb-1">Targeted Account</label>
                                <div className="flex items-center gap-2 text-red-700 dark:text-red-400 font-mono text-sm">
                                    <User className="w-4 h-4" />
                                    {incident.target_username}
                                </div>
                            </div>
                        )}

                        <div>
                            <label className="text-xs text-slate-400 block mb-1">Geo-Location</label>
                            <div className="h-32 bg-slate-100 dark:bg-slate-800 rounded-lg flex items-center justify-center relative overflow-hidden">
                                <MapPin className="text-slate-400" />
                                <span className="absolute bottom-2 left-2 text-xs font-mono text-slate-500">Lat: {incident.lat}, Lon: {incident.lon}</span>
                            </div>
                        </div>
                    </div>
                </aside>

                {/* Main Analysis */}
                <main className="flex-1 overflow-y-auto p-6 lg:p-10">
                    <div className="max-w-4xl mx-auto space-y-8">
                        {/* AI Confidence & Unidirectional Analysis */}
                        <div className="bg-white dark:bg-[#151b29] rounded-xl p-6 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col md:flex-row items-start md:items-center gap-8">
                            <div className="relative w-32 h-32 flex items-center justify-center shrink-0">
                                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                                    <path className="text-slate-100 dark:text-slate-800" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="3"></path>
                                    <path className={clsx(incident.confidence > 0.9 ? "text-red-500" : "text-amber-500")} strokeDasharray={`${incident.confidence * 100}, 100`} d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="3"></path>
                                </svg>
                                <div className="absolute inset-0 flex flex-col items-center justify-center">
                                    <span className="text-2xl font-bold text-slate-900 dark:text-white">{Math.round(incident.confidence * 100)}%</span>
                                    <span className="text-[10px] uppercase text-slate-500">Confidence</span>
                                </div>
                            </div>
                            <div className="space-y-2">
                                <div className="flex items-center gap-2">
                                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Unidirectional Threat Inference</h2>
                                    <span className="px-2 py-0.5 text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded">
                                        40 FORWARD METRICS
                                    </span>
                                </div>
                                <p className="text-slate-500 dark:text-slate-400 leading-relaxed text-sm">
                                    The model flagged <strong>{incident.type}</strong> from {incident.country} without waiting for target responses or return-path ACK packets.
                                </p>
                                <div className="p-3 bg-slate-100 dark:bg-slate-800/60 rounded-lg border border-slate-200 dark:border-slate-700/60 text-xs font-mono text-slate-300">
                                    <span className="text-cyan-400 font-bold">Detection Rationale: </span>
                                    {incident.detection_rationale || 'Forward inter-arrival jitter and volumetric ingress anomaly detected without return-path response.'}
                                </div>
                            </div>
                        </div>

                        {/* Unidirectional Forensic Telemetry Card */}
                        <div className="bg-white dark:bg-[#151b29] rounded-xl p-6 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
                                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                                    <Activity className="w-4 h-4 text-emerald-400" />
                                    Unidirectional Tap Forensics (No Reverse Channel)
                                </h3>
                                <span className="text-xs font-mono text-slate-500">Tap ID: TAP-DIODE-INGRESS-01</span>
                            </div>
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                                <div className="p-3 bg-slate-50 dark:bg-slate-800/40 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-[11px] text-slate-400">Flow Direction</div>
                                    <div className="text-sm font-bold text-emerald-400 font-mono mt-1">INGRESS [→]</div>
                                </div>
                                <div className="p-3 bg-slate-50 dark:bg-slate-800/40 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-[11px] text-slate-400">Forward Packets</div>
                                    <div className="text-sm font-bold dark:text-white font-mono mt-1">{incident.fwd_packets || 1} pkts</div>
                                </div>
                                <div className="p-3 bg-slate-50 dark:bg-slate-800/40 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-[11px] text-slate-400">Forward Volume</div>
                                    <div className="text-sm font-bold dark:text-white font-mono mt-1">
                                        {incident.fwd_bytes ? `${(incident.fwd_bytes / 1024).toFixed(1)} KB` : '1.4 KB'}
                                    </div>
                                </div>
                                <div className="p-3 bg-slate-50 dark:bg-slate-800/40 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-[11px] text-slate-400">Fwd IAT Mean</div>
                                    <div className="text-sm font-bold text-cyan-400 font-mono mt-1">
                                        {incident.fwd_iat_mean ? `${incident.fwd_iat_mean.toFixed(1)} μs` : '12.4 μs'}
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Action Panel */}
                        <div className="bg-slate-900 rounded-xl p-1 overflow-hidden">
                            <div className="bg-slate-800/50 backdrop-blur-sm p-6 rounded-lg">
                                <h3 className="text-white font-bold text-lg mb-4 flex items-center gap-2">
                                    <ShieldAlert className="text-amber-400" />
                                    Recommended Action:
                                    <span className="text-amber-300">
                                        {incident.type.includes('Brute Force') && incident.target_username ? ` Lock Account '${incident.target_username}' & Block IP` :
                                            incident.type.includes('Bot') ? ` Block IP & Rate Limit` :
                                                incident.type.includes('Port') ? ` Block IP & Close Port ${incident.destination_port}` :
                                                    " Block Source IP"}
                                    </span>
                                </h3>
                                <div className="flex flex-wrap gap-4">
                                    <button
                                        onClick={() => handleAction('BLOCK')}
                                        disabled={isResolving}
                                        className="flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-transform active:scale-95 disabled:opacity-50"
                                    >
                                        <CheckCircle className="w-5 h-5" />
                                        {isResolving ? 'Processing...' :
                                            incident.type.includes('Brute Force') ? 'Lock Account & Block' :
                                                incident.type.includes('Bot') ? 'Block & Rate Limit' :
                                                    'Approve Block'}
                                    </button>
                                    <button
                                        onClick={() => handleAction('IGNORE')}
                                        disabled={isResolving}
                                        className="flex-1 bg-slate-700 hover:bg-slate-600 text-slate-300 font-bold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-transform active:scale-95 disabled:opacity-50"
                                    >
                                        <XCircle className="w-5 h-5" />
                                        Mark as False Positive
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        </div>
    );
};

export default IncidentReview;
