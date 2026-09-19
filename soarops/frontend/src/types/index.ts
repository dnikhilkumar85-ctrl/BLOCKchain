export interface SystemHealth {
    status: "HEALTHY" | "DEGRADED";
    uptime_seconds: number;
    traffic_processed: string;
    automation_rate: string;
}

export interface Packet {
    id: number;
    timestamp: string;
    src_ip: string;
    country: string;
    lat: number;
    lon: number;
    type: string;
    confidence: number;
    destination_port: number;
    action: "MONITOR" | "AUTO_BLOCKED" | "PENDING_REVIEW" | "MANUAL_BLOCK" | "FALSE_POSITIVE";
    handled_by?: string;
    resolved_at?: string;

    // Context Data
    target_username?: string;
    burst_score?: number;
    failed_attempts?: number;
    traffic_volume?: string;
    login_behavior?: string;

    // Unidirectional Telemetry
    flow_direction?: string;
    fwd_packets?: number;
    fwd_bytes?: number;
    fwd_iat_mean?: number;
    detection_rationale?: string;
}

export interface UnidirectionalStatus {
    architecture: string;
    asymmetry_index: number;
    mode: string;
    features_evaluated: number;
    backward_channels_monitored: number;
    forward_channels_monitored: number;
    flow_direction: string;
    diode_enclave_status: string;
    total_forward_packets_analyzed: number;
    threats_detected: number;
    auto_blocked: number;
    recent_unidirectional_detections: Array<{
        ip: string;
        type: string;
        confidence: number;
        fwd_packets: number;
        fwd_bytes: number;
        fwd_iat_mean: number;
        rationale: string;
    }>;
}

export interface ChatMessage {
    role: 'user' | 'ai';
    content: string;
    timestamp: string;
}

export interface ChatSession {
    id: number;
    title: string;
    created_at: string;
    messages: ChatMessage[];
}

export interface Incident extends Packet {
    // Same structure as packet for now, but semantically distinct
}

export interface ThreatMapData {
    id: number;
    lat: number;
    lon: number;
    type: string;
    src_ip: string;
    country: string;
}
