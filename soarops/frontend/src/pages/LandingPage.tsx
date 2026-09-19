import { Link } from 'react-router-dom';
import { Shield, Lock, Radio, Activity, Cpu, ArrowRight } from 'lucide-react';

const LandingPage = () => {
    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 relative overflow-hidden font-display">
            {/* Ambient Cyber Glow */}
            <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-emerald-500/10 blur-[130px] rounded-full pointer-events-none" />
            <div className="absolute bottom-10 right-1/4 w-[450px] h-[300px] bg-blue-500/10 blur-[120px] rounded-full pointer-events-none" />

            <div className="max-w-5xl w-full z-10 flex flex-col items-center">
                {/* Header Badge */}
                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-950/70 border border-emerald-500/30 text-emerald-400 text-xs font-semibold tracking-wide uppercase mb-6 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
                    <Radio className="w-3.5 h-3.5 animate-pulse text-emerald-400" />
                    <span>Unidirectional IP Traffic &amp; Data Diode Defense</span>
                </div>

                {/* Main Title */}
                <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-center tracking-tight text-white mb-4 max-w-3xl leading-tight">
                    AI-Based Threat Detection in{' '}
                    <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400">
                        Unidirectional IP Traffic
                    </span>
                </h1>

                <p className="text-slate-400 text-center max-w-2xl text-base sm:text-lg mb-10 leading-relaxed">
                    Purpose-built network security monitoring for hardware data diodes, passive optical taps, and asymmetric ingress feeds. Detects zero-day threats, DoS floods, and blind intrusions using 40 forward-only flow telemetry features without return-path dependency.
                </p>

                {/* Key Telemetry Highlights */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 w-full max-w-3xl mb-12">
                    <div className="flex items-center gap-3 bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                        <Activity className="w-6 h-6 text-emerald-400 shrink-0" />
                        <div>
                            <div className="text-xs text-slate-400">Forward Flow Analysis</div>
                            <div className="text-sm font-semibold text-white">100% Ingress (No ACK Path)</div>
                        </div>
                    </div>
                    <div className="flex items-center gap-3 bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                        <Cpu className="w-6 h-6 text-cyan-400 shrink-0" />
                        <div>
                            <div className="text-xs text-slate-400">AI Model Architecture</div>
                            <div className="text-sm font-semibold text-white">40 Forward-Only Features</div>
                        </div>
                    </div>
                    <div className="flex items-center gap-3 bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                        <Shield className="w-6 h-6 text-blue-400 shrink-0" />
                        <div>
                            <div className="text-xs text-slate-400">Detection Accuracy</div>
                            <div className="text-sm font-semibold text-white">99.85% Multi-Class IDS</div>
                        </div>
                    </div>
                </div>

                {/* Portals Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 w-full max-w-4xl">
                    {/* Client Monitoring Portal */}
                    <Link
                        to="/client/dashboard"
                        className="group relative bg-slate-900/90 rounded-2xl p-8 border border-slate-800 hover:border-emerald-500/70 transition-all duration-300 hover:shadow-[0_0_35px_rgba(16,185,129,0.25)] overflow-hidden flex flex-col justify-between"
                    >
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-15 transition-opacity">
                            <Shield className="w-36 h-36 text-emerald-500" />
                        </div>
                        <div className="relative z-10">
                            <div className="w-14 h-14 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mb-6 group-hover:scale-105 transition-transform">
                                <Shield className="w-7 h-7 text-emerald-400" />
                            </div>
                            <h2 className="text-2xl font-bold text-white mb-2">Operations Center</h2>
                            <p className="text-slate-400 text-sm leading-relaxed mb-6">
                                Real-time monitoring of unidirectional ingress streams, forward inter-arrival variance, automated policy enforcement, and live attack maps.
                            </p>
                        </div>
                        <div className="relative z-10 flex items-center text-emerald-400 font-semibold text-sm group-hover:translate-x-1.5 transition-transform">
                            Enter Operations Console <ArrowRight className="w-4 h-4 ml-1.5" />
                        </div>
                    </Link>

                    {/* Admin Incident & Policy Portal */}
                    <Link
                        to="/admin/dashboard"
                        className="group relative bg-slate-900/90 rounded-2xl p-8 border border-slate-800 hover:border-cyan-500/70 transition-all duration-300 hover:shadow-[0_0_35px_rgba(6,182,212,0.25)] overflow-hidden flex flex-col justify-between"
                    >
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-15 transition-opacity">
                            <Lock className="w-36 h-36 text-cyan-500" />
                        </div>
                        <div className="relative z-10">
                            <div className="w-14 h-14 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mb-6 group-hover:scale-105 transition-transform">
                                <Lock className="w-7 h-7 text-cyan-400" />
                            </div>
                            <h2 className="text-2xl font-bold text-white mb-2">Incident &amp; Policy Management</h2>
                            <p className="text-slate-400 text-sm leading-relaxed mb-6">
                                Deep dive into blind threat investigations, review forward telemetry forensics, configure data diode thresholds, and export compliance audits.
                            </p>
                        </div>
                        <div className="relative z-10 flex items-center text-cyan-400 font-semibold text-sm group-hover:translate-x-1.5 transition-transform">
                            Access Security Command <ArrowRight className="w-4 h-4 ml-1.5" />
                        </div>
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default LandingPage;
