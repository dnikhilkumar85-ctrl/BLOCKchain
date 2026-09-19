import { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Shield, RefreshCw, Crosshair, Globe, Zap, Radio, Activity } from 'lucide-react';
import { useSystemHealth } from '../../../hooks/useSystemHealth';
import { apiClient } from '../../../api/client';
import type { Packet } from '../../../types';

interface DefenseGateway {
    id: string;
    name: string;
    coords: [number, number];
    region: string;
    status: string;
}

const DEFENSE_GATEWAYS: DefenseGateway[] = [
    {
        id: 'us-core',
        name: 'US-East SOAR Defense Hub',
        coords: [38.8951, -77.0364],
        region: 'Americas Hub (Virginia)',
        status: 'Active Automated Defense'
    },
    {
        id: 'eu-core',
        name: 'EMEA Security Gateway',
        coords: [50.1109, 8.6821],
        region: 'Europe / Middle East (Frankfurt)',
        status: 'Active Automated Defense'
    },
    {
        id: 'apac-core',
        name: 'APAC Threat Shield',
        coords: [35.6762, 139.6503],
        region: 'Asia-Pacific (Tokyo)',
        status: 'Active Automated Defense'
    }
];

// Route attacks to the nearest regional defense gateway
function getTargetGateway(_lat: number, lon: number): DefenseGateway {
    if (lon >= -30 && lon <= 65) {
        return DEFENSE_GATEWAYS[1]; // EMEA
    }
    if (lon > 65) {
        return DEFENSE_GATEWAYS[2]; // APAC
    }
    return DEFENSE_GATEWAYS[0]; // Americas
}

// Threat category color mapping
const THREAT_COLORS: Record<string, { hex: string; bg: string; border: string }> = {
    'DDoS': { hex: '#ef4444', bg: 'rgba(239, 68, 68, 0.25)', border: '#ef4444' },
    'DoS': { hex: '#f87171', bg: 'rgba(248, 113, 113, 0.25)', border: '#f87171' },
    'Brute Force': { hex: '#f97316', bg: 'rgba(249, 115, 22, 0.25)', border: '#f97316' },
    'Port Scanning': { hex: '#eab308', bg: 'rgba(234, 179, 8, 0.25)', border: '#eab308' },
    'Web Attacks': { hex: '#a855f7', bg: 'rgba(168, 85, 247, 0.25)', border: '#a855f7' },
    'Bots': { hex: '#06b6d4', bg: 'rgba(6, 182, 212, 0.25)', border: '#06b6d4' },
};

function getThreatColor(type: string): { hex: string; bg: string; border: string } {
    for (const key of Object.keys(THREAT_COLORS)) {
        if (type.toLowerCase().includes(key.toLowerCase())) {
            return THREAT_COLORS[key];
        }
    }
    return { hex: '#ef4444', bg: 'rgba(239, 68, 68, 0.25)', border: '#ef4444' };
}

// Generate quadratic bezier arc points between two coordinates
function generateArcPoints(start: [number, number], end: [number, number], pointsCount = 32): [number, number][] {
    const [startLat, startLon] = start;
    const [endLat, endLon] = end;

    // Calculate mid point with an upward arc offset based on distance
    const dist = Math.sqrt(Math.pow(endLat - startLat, 2) + Math.pow(endLon - startLon, 2));
    const arcHeight = Math.min(dist * 0.26, 28);
    const midLat = (startLat + endLat) / 2 + arcHeight;
    const midLon = (startLon + endLon) / 2;

    const points: [number, number][] = [];
    for (let i = 0; i <= pointsCount; i++) {
        const t = i / pointsCount;
        const lat = Math.pow(1 - t, 2) * startLat + 2 * (1 - t) * t * midLat + Math.pow(t, 2) * endLat;
        const lon = Math.pow(1 - t, 2) * startLon + 2 * (1 - t) * t * midLon + Math.pow(t, 2) * endLon;
        points.push([lat, lon]);
    }
    return points;
}

interface ActiveVector {
    instanceId: string;
    threat: Packet;
    spawnedAt: number;
    ttl: number; // Duration in ms before fading out
}

const ThreatMap = () => {
    const { health } = useSystemHealth();
    const mapContainerRef = useRef<HTMLDivElement>(null);
    const mapRef = useRef<L.Map | null>(null);
    const markersLayerRef = useRef<L.LayerGroup | null>(null);
    const arcsLayerRef = useRef<L.LayerGroup | null>(null);
    const markersMapRef = useRef<Map<string, L.Marker>>(new Map());

    // Master pool of threats fetched from the server
    const threatsPoolRef = useRef<Packet[]>([]);
    const poolIndexRef = useRef<number>(0);

    // Active in-flight vectors (constantly cycle and expire)
    const [activeVectors, setActiveVectors] = useState<ActiveVector[]>([]);
    const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
    const [selectedThreat, setSelectedThreat] = useState<Packet | null>(null);
    const [totalDetected, setTotalDetected] = useState<number>(0);
    const [isLoading, setIsLoading] = useState<boolean>(true);

    // Fetch threats from API and replenish the pool
    const fetchThreats = async () => {
        try {
            const response = await apiClient.get<Packet[]>('/threats/map');
            const data: Packet[] = response.data || [];
            if (data.length > 0) {
                threatsPoolRef.current = data.filter(t => t.lat !== 0 || t.lon !== 0);
                setTotalDetected(data.length);
            } else {
                const liveResp = await apiClient.get<Packet[]>('/traffic/live');
                const threats = liveResp.data.filter(p => p.type !== 'Normal Traffic' && (p.lat !== 0 || p.lon !== 0));
                threatsPoolRef.current = threats;
                setTotalDetected(threats.length);
            }
        } catch (err) {
            console.error('Failed to fetch threat map data:', err);
        } finally {
            setIsLoading(false);
        }
    };

    // 1. Initialize Map once
    useEffect(() => {
        if (!mapContainerRef.current || mapRef.current) return;

        const map = L.map(mapContainerRef.current, {
            center: [26, 10],
            zoom: 2.3,
            minZoom: 1.8,
            maxZoom: 9,
            zoomControl: false,
            attributionControl: false,
            worldCopyJump: true,
        });

        // Sleek ESRI Dark Gray Canvas tiles (clean, high-contrast, zero watermarks)
        L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
            maxZoom: 16,
            attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
        }).addTo(map);

        L.control.zoom({ position: 'bottomright' }).addTo(map);

        const arcsGroup = L.layerGroup().addTo(map);
        const markersGroup = L.layerGroup().addTo(map);

        arcsLayerRef.current = arcsGroup;
        markersLayerRef.current = markersGroup;
        mapRef.current = map;

        // Render all 3 Regional Defense Gateways (US, EMEA, APAC)
        DEFENSE_GATEWAYS.forEach(gateway => {
            const targetIcon = L.divIcon({
                className: 'custom-soc-marker',
                html: `
                    <div style="position: relative; width: 34px; height: 34px; display: flex; align-items: center; justify-content: center;">
                        <div class="cyber-pulse-ring" style="position: absolute; width: 34px; height: 34px; border-radius: 50%; background: rgba(56, 189, 248, 0.35); border: 1.5px solid #38bdf8;"></div>
                        <div style="width: 14px; height: 14px; border-radius: 50%; background: #38bdf8; box-shadow: 0 0 16px #38bdf8; border: 2px solid #ffffff; z-index: 2;"></div>
                    </div>
                `,
                iconSize: [34, 34],
                iconAnchor: [17, 17],
            });

            const targetMarker = L.marker(gateway.coords, { icon: targetIcon });
            targetMarker.bindPopup(`
                <div style="font-family: sans-serif; font-size: 12px; color: #f1f5f9; min-width: 200px;">
                    <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                        🛡️ ${gateway.name}
                    </div>
                    <div style="color: #94a3b8; margin-bottom: 2px;">Gateway: ${gateway.region}</div>
                    <div style="color: #34d399; font-weight: 600;">Status: ${gateway.status}</div>
                </div>
            `);
            targetMarker.addTo(map);
        });

        setTimeout(() => {
            map.invalidateSize();
        }, 150);

        return () => {
            map.remove();
            mapRef.current = null;
        };
    }, []);

    // 2. Initial and periodic background data replenishment
    useEffect(() => {
        fetchThreats();
        const timer = setInterval(fetchThreats, 2500);
        return () => clearInterval(timer);
    }, []);

    // 3. Real-Time Vector Lifecycle Engine: spawns new attacks & expires old ones every 850ms
    useEffect(() => {
        const streamTicker = setInterval(() => {
            const pool = threatsPoolRef.current;
            if (pool.length === 0) return;

            const now = Date.now();
            const TTL = 4500; // Each vector lives for 4.5 seconds

            // Filter by active category if selected
            const candidates = selectedCategory === 'ALL'
                ? pool
                : pool.filter(t => t.type.toLowerCase().includes(selectedCategory.toLowerCase()));

            if (candidates.length === 0) return;

            // Pick the next threat from the pool
            const nextThreat = candidates[poolIndexRef.current % candidates.length];
            poolIndexRef.current = (poolIndexRef.current + 1) % candidates.length;

            setActiveVectors(prev => {
                // Purge expired vectors
                const alive = prev.filter(v => now - v.spawnedAt < v.ttl);

                // Add the fresh incoming attack
                const newVector: ActiveVector = {
                    instanceId: `${nextThreat.id}_${now}_${Math.random().toString(36).substring(2, 5)}`,
                    threat: nextThreat,
                    spawnedAt: now,
                    ttl: TTL,
                };

                // Keep maximum 7 concurrent active vectors on screen so it's always clean and constantly shifting!
                return [...alive.slice(-6), newVector];
            });
        }, 850);

        return () => clearInterval(streamTicker);
    }, [selectedCategory]);

    // 4. Update Leaflet Map Layers whenever activeVectors changes
    useEffect(() => {
        if (!mapRef.current || !markersLayerRef.current || !arcsLayerRef.current) return;

        const markersGroup = markersLayerRef.current;
        const arcsGroup = arcsLayerRef.current;

        markersGroup.clearLayers();
        arcsGroup.clearLayers();
        markersMapRef.current.clear();

        activeVectors.forEach((vector) => {
            const threat = vector.threat;
            const colors = getThreatColor(threat.type);
            const sourceCoords: [number, number] = [threat.lat, threat.lon];
            const targetGateway = getTargetGateway(threat.lat, threat.lon);

            // 1. Draw dynamic Attack Arc from Source to Regional Gateway
            const arcPoints = generateArcPoints(sourceCoords, targetGateway.coords);
            const polyline = L.polyline(arcPoints, {
                color: colors.hex,
                weight: 2.5,
                className: 'live-attack-arc',
            });
            polyline.addTo(arcsGroup);

            // 2. Custom HTML Marker with shockwave blast wave
            const markerIcon = L.divIcon({
                className: 'threat-marker',
                html: `
                    <div style="position: relative; width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; cursor: pointer;">
                        <div class="blast-wave-ring" style="position: absolute; width: 28px; height: 28px; border-radius: 50%; background: ${colors.bg}; border: 1.5px solid ${colors.border};"></div>
                        <div style="width: 11px; height: 11px; border-radius: 50%; background: ${colors.hex}; box-shadow: 0 0 12px ${colors.hex}; border: 2px solid #ffffff; z-index: 2;"></div>
                    </div>
                `,
                iconSize: [28, 28],
                iconAnchor: [14, 14],
            });

            const marker = L.marker(sourceCoords, { icon: markerIcon });

            const popupContent = `
                <div style="font-family: inherit; font-size: 12px; color: #f8fafc; min-width: 230px;">
                    <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 6px; margin-bottom: 8px;">
                        <span style="font-weight: 700; color: ${colors.hex}; text-transform: uppercase; letter-spacing: 0.05em; font-size: 13px;">
                            ${threat.type}
                        </span>
                        <span style="font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 600; background: ${
                            threat.action === 'AUTO_BLOCKED' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(234, 179, 8, 0.2)'
                        }; color: ${
                            threat.action === 'AUTO_BLOCKED' ? '#34d399' : '#facc15'
                        }; border: 1px solid ${
                            threat.action === 'AUTO_BLOCKED' ? '#059669' : '#ca8a04'
                        };">
                            ${threat.action}
                        </span>
                    </div>
                    <div style="display: grid; grid-template-columns: 85px 1fr; gap: 4px 8px; font-size: 11px;">
                        <span style="color: #94a3b8;">Source IP:</span>
                        <span style="font-family: monospace; color: #38bdf8; font-weight: 600;">${threat.src_ip}</span>

                        <span style="color: #94a3b8;">Origin:</span>
                        <span style="color: #e2e8f0; font-weight: 500;">${threat.country}</span>

                        <span style="color: #94a3b8;">Target Hub:</span>
                        <span style="color: #38bdf8; font-weight: 500;">${targetGateway.name}</span>

                        <span style="color: #94a3b8;">Target Port:</span>
                        <span style="color: #e2e8f0; font-family: monospace;">Port ${threat.destination_port || '80'}</span>

                        <span style="color: #94a3b8;">Confidence:</span>
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <div style="flex: 1; height: 5px; background: #334155; border-radius: 3px; overflow: hidden;">
                                <div style="width: ${(threat.confidence * 100).toFixed(0)}%; height: 100%; background: ${colors.hex}; border-radius: 3px;"></div>
                            </div>
                            <span style="font-weight: 600; color: #f1f5f9;">${(threat.confidence * 100).toFixed(1)}%</span>
                        </div>

                        ${threat.failed_attempts ? `
                            <span style="color: #94a3b8;">Failed Logins:</span>
                            <span style="color: #f87171; font-weight: 600;">${threat.failed_attempts}</span>
                        ` : ''}
                    </div>
                </div>
            `;

            marker.bindPopup(popupContent);
            marker.on('click', () => {
                setSelectedThreat(threat);
            });

            marker.addTo(markersGroup);
            markersMapRef.current.set(vector.instanceId, marker);
        });
    }, [activeVectors]);

    // Handle clicking a threat in the sidebar to fly to it
    const handleFocusThreat = (vector: ActiveVector) => {
        const threat = vector.threat;
        setSelectedThreat(threat);
        if (!mapRef.current || (threat.lat === 0 && threat.lon === 0)) return;

        mapRef.current.flyTo([threat.lat, threat.lon], 4.5, {
            duration: 1.2,
        });

        const marker = markersMapRef.current.get(vector.instanceId);
        if (marker) {
            marker.openPopup();
        }
    };

    // Reset view to global overview
    const handleResetView = () => {
        if (!mapRef.current) return;
        mapRef.current.flyTo([26, 10], 2.3, { duration: 1 });
        setSelectedThreat(null);
    };

    const categories = ['ALL', 'DDoS', 'DoS', 'Port Scanning', 'Brute Force', 'Web Attacks'];

    return (
        <div className="relative w-full h-[calc(100vh-4rem)] bg-background-dark overflow-hidden flex flex-col font-display">
            {/* Real Interactive Leaflet Map Container */}
            <div ref={mapContainerRef} className="absolute inset-0 z-0 h-full w-full" />

            {/* Subtle cyber scanlines overlay */}
            <div className="scanlines absolute inset-0 z-[1] pointer-events-none opacity-20" />

            {/* Top Operations HUD Header */}
            <div className="absolute top-0 left-0 right-0 p-4 md:p-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 z-10 pointer-events-none">
                <div className="pointer-events-auto bg-surface-dark/80 backdrop-blur-md border border-slate-700/60 p-3.5 rounded-xl shadow-2xl">
                    <div className="flex items-center gap-2 mb-1">
                        <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                        <h1 className="text-xs uppercase tracking-[0.25em] text-slate-400 font-semibold">Global Threat Intelligence</h1>
                    </div>
                    <div className="flex items-center gap-2">
                        <Shield className="w-5 h-5 text-primary" />
                        <h2 className="text-lg md:text-xl font-bold text-white tracking-tight">SOAR Live Defense Grid</h2>
                        <span className="text-[10px] bg-emerald-500/20 text-emerald-400 font-semibold px-2 py-0.5 rounded border border-emerald-500/30 flex items-center gap-1">
                            <Radio className="w-3 h-3 animate-spin" /> LIVE STREAM ACTIVE
                        </span>
                    </div>
                </div>

                {/* Live Stats Ticker */}
                <div className="hidden md:flex gap-3 pointer-events-auto">
                    <div className="bg-surface-dark/80 backdrop-blur-md border border-slate-700/60 px-4 py-2 rounded-xl flex flex-col items-center min-w-[110px] shadow-lg">
                        <span className="text-[10px] uppercase tracking-wider text-slate-400">In-Flight Vectors</span>
                        <span className="text-lg font-bold text-cyan-400 font-mono flex items-center gap-1">
                            <Activity className="w-4 h-4 animate-pulse text-cyan-400" />
                            {activeVectors.length}
                        </span>
                    </div>
                    <div className="bg-surface-dark/80 backdrop-blur-md border border-slate-700/60 px-4 py-2 rounded-xl flex flex-col items-center min-w-[110px] shadow-lg">
                        <span className="text-[10px] uppercase tracking-wider text-slate-400">Total Scanned</span>
                        <span className="text-lg font-bold text-red-400 font-mono">{totalDetected || 100}+</span>
                    </div>
                    <div className="bg-surface-dark/80 backdrop-blur-md border border-slate-700/60 px-4 py-2 rounded-xl flex flex-col items-center min-w-[110px] border-l-2 border-l-primary shadow-lg">
                        <span className="text-[10px] uppercase tracking-wider text-slate-400">Auto-Blocked</span>
                        <span className="text-lg font-bold text-primary font-mono">{health?.automation_rate || '99.9%'}</span>
                    </div>
                    <button
                        onClick={handleResetView}
                        title="Reset Camera View"
                        className="bg-surface-dark/80 hover:bg-slate-700/80 backdrop-blur-md border border-slate-700/60 p-2.5 rounded-xl text-slate-300 hover:text-white transition-colors flex items-center justify-center shadow-lg"
                    >
                        <Crosshair className="w-5 h-5 text-cyan-400" />
                    </button>
                </div>
            </div>

            {/* Category Filter Pills */}
            <div className="absolute top-24 left-4 md:left-6 z-10 flex flex-wrap gap-1.5 pointer-events-auto max-w-xl">
                {categories.map(cat => {
                    const active = selectedCategory === cat;
                    return (
                        <button
                            key={cat}
                            onClick={() => setSelectedCategory(cat)}
                            className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all backdrop-blur-md border ${
                                active
                                    ? 'bg-primary text-white border-primary shadow-lg shadow-primary/30'
                                    : 'bg-surface-dark/80 text-slate-400 border-slate-700/60 hover:text-white hover:bg-slate-800/80'
                            }`}
                        >
                            {cat}
                        </button>
                    );
                })}
            </div>

            {/* Bottom-Left: Live Transient Vectors Stream */}
            <div className="absolute bottom-6 left-4 md:left-6 w-84 max-h-84 bg-surface-dark/85 backdrop-blur-md border border-slate-700/60 rounded-xl p-4 hidden md:flex flex-col z-10 shadow-2xl border-l-4 border-l-alert-orange">
                <div className="flex justify-between items-center mb-3">
                    <div className="flex items-center gap-2">
                        <Zap className="w-4 h-4 text-alert-orange animate-bounce" />
                        <h3 className="text-xs font-bold uppercase tracking-wider text-white">Live Interceptions</h3>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="text-[10px] bg-alert-orange/20 text-alert-orange px-1.5 py-0.5 rounded border border-alert-orange/30 font-mono">
                            {activeVectors.length} ACTIVE
                        </span>
                        <button
                            onClick={fetchThreats}
                            disabled={isLoading}
                            className="text-slate-400 hover:text-white transition-colors"
                        >
                            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-primary' : ''}`} />
                        </button>
                    </div>
                </div>

                <div className="overflow-y-auto space-y-2 pr-1 flex-1">
                    {activeVectors.map((vector) => {
                        const threat = vector.threat;
                        const color = getThreatColor(threat.type);
                        const isSelected = selectedThreat?.id === threat.id;
                        const target = getTargetGateway(threat.lat, threat.lon);

                        return (
                            <div
                                key={vector.instanceId}
                                onClick={() => handleFocusThreat(vector)}
                                className={`flex items-center justify-between text-xs p-2 rounded-lg cursor-pointer transition-all border ${
                                    isSelected
                                        ? 'bg-primary/20 border-primary text-white'
                                        : 'bg-slate-900/70 border-slate-800 hover:bg-white/5 hover:border-slate-700'
                                }`}
                            >
                                <div className="flex items-center gap-2 min-w-0">
                                    <span
                                        className="w-2.5 h-2.5 rounded-full flex-shrink-0 animate-ping"
                                        style={{ backgroundColor: color.hex }}
                                    />
                                    <div className="truncate">
                                        <p className="font-semibold text-slate-200 truncate">{threat.type}</p>
                                        <p className="text-[10px] text-slate-400 font-mono truncate">{threat.src_ip}</p>
                                    </div>
                                </div>
                                <div className="text-right flex-shrink-0 ml-2">
                                    <span className="text-[11px] font-mono text-cyan-400 font-semibold">{threat.country}</span>
                                    <div className="text-[10px] text-slate-400">
                                        → {target.id === 'us-core' ? 'US' : target.id === 'eu-core' ? 'EU' : 'APAC'} • {(threat.confidence * 100).toFixed(0)}%
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                    {activeVectors.length === 0 && (
                        <div className="text-xs text-slate-500 text-center py-6 flex flex-col items-center gap-2">
                            <Globe className="w-6 h-6 text-slate-600 animate-pulse" />
                            <span>Intercepting live incoming vectors...</span>
                        </div>
                    )}
                </div>
            </div>

            {/* Bottom-Right Legend */}
            <div className="absolute bottom-6 right-16 hidden lg:flex items-center gap-3 bg-surface-dark/85 backdrop-blur-md border border-slate-700/60 px-3.5 py-2 rounded-xl z-10 shadow-xl">
                <span className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">Vectors:</span>
                {Object.entries(THREAT_COLORS).map(([name, c]) => (
                    <div key={name} className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: c.hex }} />
                        <span className="text-[11px] text-slate-300">{name}</span>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ThreatMap;
