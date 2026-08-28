import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { 
  Layers, 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  Minimize2, 
  Compass, 
  Navigation
} from "lucide-react";

// Fix Leaflet default icon paths
import iconUrl       from "leaflet/dist/images/marker-icon.png";
import iconRetinaUrl from "leaflet/dist/images/marker-icon-2x.png";
import shadowUrl     from "leaflet/dist/images/marker-shadow.png";

delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({ iconUrl, iconRetinaUrl, shadowUrl });

export interface GeoPoint {
  lat: number;
  lng: number;
  label: string;
  pointType?: "sender" | "server" | "hop";
  city?: string;
  country?: string;
  ip?: string;
  isp?: string;
  org?: string;
  isOrigin?: boolean;
  isSynthetic?: boolean;
  verificationSource?: string;
}

interface GeoMapProps {
  points?: GeoPoint[];
  height?: number;
  isSynthetic?: boolean;
}

type MapLayerType = "satellite" | "streets" | "dark";

// Tile Layer Definitions (100% Free, Zero Key Required)
const MAP_LAYERS = {
  satellite: {
    name: "Satellite HD",
    icon: "🛰️",
    base: "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
    labels: "https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}",
    maxZoom: 18,
    attribution: "&copy; Esri World Imagery"
  },
  streets: {
    name: "Detailed Streets",
    icon: "🗺️",
    base: "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    labels: null,
    maxZoom: 19,
    attribution: "&copy; OpenStreetMap Contributors"
  },
  dark: {
    name: "Cyber Dark HUD",
    icon: "🕶️",
    base: "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
    labels: "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
    maxZoom: 16,
    attribution: "&copy; Esri &copy; OpenStreetMap"
  }
};

function calculateDistanceKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth's radius in km
  const dLat = (lat2 - lat1) * (Math.PI / 180);
  const dLon = (lon2 - lon1) * (Math.PI / 180);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * (Math.PI / 180)) * Math.cos(lat2 * (Math.PI / 180)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

function makeCustomMarker(pt: GeoPoint): L.DivIcon {
  const type = pt.pointType || (pt.isOrigin ? "server" : "hop");
  
  let color = "#06b6d4";
  let size = 16;
  let pulseRing = "";
  let badgeLetter = "H";

  if (type === "sender") {
    color = "#a855f7"; // Purple for verified sender identity
    size = 22;
    badgeLetter = "S";
    pulseRing = `
      <div style="
        position:absolute; inset:-10px; border-radius:50%;
        border:2px solid rgba(168,85,247,0.7);
        animation:geo-ping-purple 2.2s ease-out infinite;
      "></div>
      <div style="
        position:absolute; inset:-18px; border-radius:50%;
        border:1px dashed rgba(168,85,247,0.4);
        animation:geo-spin 12s linear infinite;
      "></div>
    `;
  } else if (type === "server" || pt.isOrigin) {
    color = pt.isSynthetic ? "#f59e0b" : "#ef4444"; // Red for physical server origin
    size = 22;
    badgeLetter = "M";
    pulseRing = `
      <div style="
        position:absolute; inset:-10px; border-radius:50%;
        border:2px solid ${color}99;
        animation:geo-ping-red 1.9s ease-out infinite;
      "></div>
      <div style="
        position:absolute; inset:-18px; border-radius:50%;
        border:1px dashed ${color}55;
        animation:geo-spin-reverse 10s linear infinite;
      "></div>
    `;
  }

  return L.divIcon({
    className: "",
    iconSize:   [size + 24, size + 24],
    iconAnchor: [Math.round((size + 24) / 2), Math.round((size + 24) / 2)],
    popupAnchor:[0, -Math.round((size + 24) / 2)],
    html: `
      <div style="
        position:relative;
        width:${size + 24}px;
        height:${size + 24}px;
        display:flex;
        align-items:center;
        justify-content:center;
        cursor:pointer;
      ">
        ${pulseRing}
        <div style="
          width:${size}px;
          height:${size}px;
          border-radius:50%;
          background:${color};
          border:3px solid #ffffff;
          box-shadow:0 0 16px ${color}, 0 0 32px ${color}88;
          display:flex;
          align-items:center;
          justify-content:center;
          flex-shrink:0;
          z-index:10;
        ">
          <span style="font-size:10px;color:#ffffff;font-weight:900;font-family:'JetBrains Mono',monospace;">${badgeLetter}</span>
        </div>
      </div>
    `,
  });
}

function makePopupHtml(pt: GeoPoint, idx: number, totalDist?: number): string {
  const type = pt.pointType || (pt.isOrigin ? "server" : "hop");
  
  let headerColor = "#06b6d4";
  let title = `▸ RELAY HOP #${idx}`;
  let typeBadge = "TRANSIT NODE";

  if (type === "sender") {
    headerColor = "#a855f7";
    title = "👤 SENDER IDENTITY ORIGIN";
    typeBadge = "CLAIMED SENDER HQ";
  } else if (type === "server" || pt.isOrigin) {
    headerColor = pt.isSynthetic ? "#f59e0b" : "#ef4444";
    title = pt.isSynthetic ? "⚠ TRANSMISSION GATEWAY" : "🖥️ PHYSICAL TRANSMISSION SERVER";
    typeBadge = "HOSTING / MTA GATEWAY";
  }

  return `
    <div style="
      font-family:'JetBrains Mono',monospace;
      background:rgba(6, 16, 26, 0.95);
      border:1px solid ${headerColor}88;
      border-radius:12px;
      padding:14px 16px;
      min-width:260px;
      max-width:320px;
      box-shadow:0 12px 40px rgba(0,0,0,0.9), 0 0 20px ${headerColor}33;
      backdrop-filter:blur(12px);
    ">
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
        <span style="color:${headerColor};font-size:9px;font-weight:900;letter-spacing:0.14em;">
          ${title}
        </span>
        <span style="background:${headerColor}22;color:${headerColor};font-size:8px;font-weight:800;padding:2px 6px;border-radius:4px;border:1px solid ${headerColor}44;">
          ${typeBadge}
        </span>
      </div>

      <div style="margin-bottom:8px;border-bottom:1px solid rgba(255,255,255,0.08);padding-bottom:6px;">
        <p style="color:#ffffff;font-size:14px;font-weight:800;margin:0 0 2px 0;">
          ${pt.city || "Unknown"}, ${pt.country || "Unknown"}
        </p>
        <p style="color:#94a3b8;font-size:10px;margin:0;">
          Coordinates: ${pt.lat.toFixed(4)}°, ${pt.lng.toFixed(4)}°
        </p>
      </div>

      <div style="display:flex;flex-direction:column;gap:3px;font-size:10px;">
        ${pt.org ? `<p style="color:#cbd5e1;margin:0;"><b style="color:#64748b;">Org:</b> ${pt.org}</p>` : ""}
        ${pt.ip && pt.ip !== "Unknown" ? `<p style="color:${headerColor};margin:0;"><b style="color:#64748b;">IP:</b> ${pt.ip}</p>` : ""}
        ${pt.isp && pt.isp !== "Unknown" ? `<p style="color:#94a3b8;margin:0;"><b style="color:#64748b;">ISP/ASN:</b> ${pt.isp}</p>` : ""}
      </div>

      ${totalDist ? `
        <div style="margin-top:8px;padding-top:6px;border-top:1px solid rgba(255,255,255,0.08);color:#e2e8f0;font-size:10px;display:flex;align-items:center;justify-content:space-between;">
          <span style="color:#64748b;">Trajectory Distance:</span>
          <span style="color:#a855f7;font-weight:800;">${totalDist.toLocaleString()} km</span>
        </div>
      ` : ""}

      ${pt.verificationSource ? `
        <div style="margin-top:8px;padding-top:6px;border-top:1px solid rgba(255,255,255,0.08);color:#10b981;font-size:9px;font-weight:700;display:flex;align-items:center;gap:4px;">
          <span>✓</span>
          <span>${pt.verificationSource}</span>
        </div>
      ` : ""}
    </div>
  `;
}

export function GeoMap({ points = [], height = 460 }: GeoMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef       = useRef<L.Map | null>(null);
  const layerGroupRef = useRef<L.LayerGroup | null>(null);
  const [activeLayer, setActiveLayer] = useState<MapLayerType>("satellite");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [cursorPos, setCursorPos] = useState<{ lat: number; lng: number } | null>(null);
  const [showLayerMenu, setShowLayerMenu] = useState(false);

  // Filter valid points with non-zero coordinates
  const validPoints = points.filter(p => p && (p.lat !== 0 || p.lng !== 0) && !isNaN(p.lat) && !isNaN(p.lng));

  // Compute sender-to-server trajectory distance
  const senderPoint = validPoints.find(p => p.pointType === "sender");
  const serverPoint = validPoints.find(p => p.pointType === "server" || p.isOrigin);
  const trajectoryDistance = (senderPoint && serverPoint) 
    ? calculateDistanceKm(senderPoint.lat, senderPoint.lng, serverPoint.lat, serverPoint.lng)
    : undefined;

  // Initialize Map
  useEffect(() => {
    if (!containerRef.current) return;

    if (mapRef.current) {
      mapRef.current.remove();
      mapRef.current = null;
    }

    const centerLat = validPoints.length > 0 ? validPoints[0].lat : 20.0;
    const centerLng = validPoints.length > 0 ? validPoints[0].lng : 0.0;
    const defaultZoom = validPoints.length > 0 ? 4 : 2;

    try {
      const map = L.map(containerRef.current, {
        center:             [centerLat, centerLng],
        zoom:               defaultZoom,
        zoomControl:        false,
        attributionControl: false,
        scrollWheelZoom:    true,
        dragging:           true,
      });

      mapRef.current = map;
      layerGroupRef.current = L.layerGroup().addTo(map);

      // Track mouse coordinates
      map.on("mousemove", (e) => {
        setCursorPos({ lat: e.latlng.lat, lng: e.latlng.lng });
      });

      map.on("mouseout", () => {
        setCursorPos(null);
      });

      // Fit bounds
      if (validPoints.length === 1) {
        map.setView([validPoints[0].lat, validPoints[0].lng], 5);
      } else if (validPoints.length > 1) {
        const bounds = L.latLngBounds(validPoints.map(p => [p.lat, p.lng] as L.LatLngTuple));
        map.fitBounds(bounds, { padding: [60, 60], maxZoom: 8 });
      }

      // Auto resize handling
      map.invalidateSize();
      const t1 = setTimeout(() => map.invalidateSize(), 100);
      const t2 = setTimeout(() => map.invalidateSize(), 400);

      return () => {
        clearTimeout(t1);
        clearTimeout(t2);
        if (mapRef.current) {
          mapRef.current.remove();
          mapRef.current = null;
        }
      };
    } catch (e) {
      console.error("Map initialization error:", e);
    }
  }, []);

  // Update Tile Layers & Markers when activeLayer or points change
  useEffect(() => {
    if (!mapRef.current || !layerGroupRef.current) return;

    const lg = layerGroupRef.current;
    lg.clearLayers();

    // 1. Add Active Tile Layer
    const layerConfig = MAP_LAYERS[activeLayer];
    const baseTile = L.tileLayer(layerConfig.base, {
      maxZoom: layerConfig.maxZoom,
      attribution: layerConfig.attribution,
    });
    lg.addLayer(baseTile);

    // Optional labels overlay for Satellite or Dark HUD
    if (layerConfig.labels) {
      const labelsTile = L.tileLayer(layerConfig.labels, {
        maxZoom: layerConfig.maxZoom,
      });
      lg.addLayer(labelsTile);
    }

    // 2. Draw Geodesic Trajectory Routes
    if (validPoints.length > 1) {
      const latlngs = validPoints.map(p => [p.lat, p.lng] as L.LatLngTuple);

      // Deep Purple Glow Polyline
      const glow = L.polyline(latlngs, {
        color:   "#a855f7",
        weight:  8,
        opacity: 0.4,
        lineCap: "round",
      });
      lg.addLayer(glow);

      // Cyan Dashed Primary Transmission Arc
      const line = L.polyline(latlngs, {
        color:     "#06b6d4",
        weight:    3,
        opacity:   0.95,
        dashArray: "8 6",
        lineCap:   "round",
      });
      lg.addLayer(line);
    }

    // 3. Add Custom Interactive Markers
    validPoints.forEach((pt, i) => {
      const icon   = makeCustomMarker(pt);
      const marker = L.marker([pt.lat, pt.lng], { icon });
      const popup  = L.popup({
        className:      "ofm-popup",
        closeButton:    false,
        offset:         [0, -6],
        maxWidth:       340,
        autoPanPadding: [30, 30],
      }).setContent(makePopupHtml(pt, i + 1, trajectoryDistance));

      marker.bindPopup(popup);
      lg.addLayer(marker);
    });

  }, [activeLayer, JSON.stringify(validPoints)]);

  const handleZoomIn = () => {
    if (mapRef.current) mapRef.current.zoomIn();
  };

  const handleZoomOut = () => {
    if (mapRef.current) mapRef.current.zoomOut();
  };

  const handleFitBounds = () => {
    if (!mapRef.current) return;
    if (validPoints.length === 1) {
      mapRef.current.setView([validPoints[0].lat, validPoints[0].lng], 6);
    } else if (validPoints.length > 1) {
      const bounds = L.latLngBounds(validPoints.map(p => [p.lat, p.lng] as L.LatLngTuple));
      mapRef.current.fitBounds(bounds, { padding: [60, 60], maxZoom: 8 });
    }
  };

  const hasSender = validPoints.some(p => p.pointType === "sender");
  const hasServer = validPoints.some(p => p.pointType === "server" || p.isOrigin);

  return (
    <div
      className={`relative rounded-2xl overflow-hidden shadow-2xl transition-all ${
        isFullscreen ? "fixed inset-4 z-[9999] shadow-[0_0_80px_rgba(0,0,0,0.95)]" : ""
      }`}
      style={{
        height: isFullscreen ? "calc(100vh - 32px)" : height,
        background: "#030712",
        border: "1px solid rgba(0, 240, 255, 0.25)",
      }}
    >
      {/* Map DOM Container */}
      <div ref={containerRef} style={{ width: "100%", height: "100%" }} />

      {/* --- TOP-LEFT: HUD TELEMETRY BADGE --- */}
      <div className="absolute top-4 left-4 z-[1000] flex flex-col gap-2 pointer-events-none">
        <div
          className="px-3.5 py-2 rounded-xl font-mono text-[10px] font-bold tracking-widest text-cyan-300 flex items-center gap-2.5 shadow-xl"
          style={{
            background: "rgba(3, 7, 18, 0.92)",
            border: "1px solid rgba(0, 240, 255, 0.4)",
            backdropFilter: "blur(12px)",
          }}
        >
          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>GEOSPATIAL INTELLIGENCE · RADAR ACTIVE</span>
        </div>

        {trajectoryDistance !== undefined && (
          <div
            className="px-3 py-1.5 rounded-lg font-mono text-[9px] text-slate-300 flex items-center gap-2 shadow-lg"
            style={{
              background: "rgba(3, 7, 18, 0.88)",
              border: "1px solid rgba(168, 85, 247, 0.4)",
              backdropFilter: "blur(8px)",
            }}
          >
            <Navigation className="w-3 h-3 text-purple-400" />
            <span>TRAJECTORY: <strong className="text-purple-300">{trajectoryDistance.toLocaleString()} km</strong></span>
          </div>
        )}
      </div>

      {/* --- TOP-RIGHT: INTERACTIVE CONTROLS (Layer Switcher, Zoom, Center, Fullscreen) --- */}
      <div className="absolute top-4 right-4 z-[1000] flex items-center gap-2">
        {/* Layer Selector */}
        <div className="relative">
          <button
            onClick={() => setShowLayerMenu(!showLayerMenu)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl font-mono text-[11px] font-bold text-slate-200 transition shadow-xl"
            style={{
              background: "rgba(3, 7, 18, 0.92)",
              border: "1px solid rgba(255, 255, 255, 0.15)",
              backdropFilter: "blur(10px)",
            }}
            title="Switch Map Layers"
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>{MAP_LAYERS[activeLayer].icon} {MAP_LAYERS[activeLayer].name}</span>
          </button>

          {showLayerMenu && (
            <div
              className="absolute right-0 mt-2 w-48 rounded-xl p-1.5 flex flex-col gap-1 shadow-2xl z-[1010]"
              style={{
                background: "rgba(6, 12, 24, 0.96)",
                border: "1px solid rgba(0, 240, 255, 0.3)",
                backdropFilter: "blur(16px)",
              }}
            >
              {(Object.keys(MAP_LAYERS) as MapLayerType[]).map((key) => {
                const l = MAP_LAYERS[key];
                const active = activeLayer === key;
                return (
                  <button
                    key={key}
                    onClick={() => {
                      setActiveLayer(key);
                      setShowLayerMenu(false);
                    }}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg text-[11px] font-mono font-semibold text-left transition ${
                      active
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                        : "text-slate-300 hover:bg-white/[0.06] hover:text-white"
                    }`}
                  >
                    <span>{l.icon}</span>
                    <span>{l.name}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Center / Fit Bounds Button */}
        <button
          onClick={handleFitBounds}
          className="p-2 rounded-xl text-slate-300 hover:text-cyan-300 transition shadow-xl"
          style={{
            background: "rgba(3, 7, 18, 0.92)",
            border: "1px solid rgba(255, 255, 255, 0.15)",
            backdropFilter: "blur(10px)",
          }}
          title="Fit & Center Route"
        >
          <Compass className="w-4 h-4 text-cyan-400" />
        </button>

        {/* Zoom In */}
        <button
          onClick={handleZoomIn}
          className="p-2 rounded-xl text-slate-300 hover:text-white transition shadow-xl"
          style={{
            background: "rgba(3, 7, 18, 0.92)",
            border: "1px solid rgba(255, 255, 255, 0.15)",
            backdropFilter: "blur(10px)",
          }}
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>

        {/* Zoom Out */}
        <button
          onClick={handleZoomOut}
          className="p-2 rounded-xl text-slate-300 hover:text-white transition shadow-xl"
          style={{
            background: "rgba(3, 7, 18, 0.92)",
            border: "1px solid rgba(255, 255, 255, 0.15)",
            backdropFilter: "blur(10px)",
          }}
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>

        {/* Fullscreen Toggle */}
        <button
          onClick={() => setIsFullscreen(!isFullscreen)}
          className="p-2 rounded-xl text-slate-300 hover:text-white transition shadow-xl"
          style={{
            background: "rgba(3, 7, 18, 0.92)",
            border: "1px solid rgba(255, 255, 255, 0.15)",
            backdropFilter: "blur(10px)",
          }}
          title={isFullscreen ? "Exit Fullscreen" : "Expand Fullscreen"}
        >
          {isFullscreen ? <Minimize2 className="w-4 h-4 text-amber-400" /> : <Maximize2 className="w-4 h-4 text-cyan-400" />}
        </button>
      </div>

      {/* --- BOTTOM-LEFT: RADAR LEGEND & ENTITY BADGES --- */}
      <div className="absolute bottom-4 left-4 z-[1000] flex flex-wrap items-center gap-2 pointer-events-none">
        <div
          className="flex items-center gap-3.5 px-3.5 py-2 rounded-xl shadow-2xl"
          style={{
            background: "rgba(3, 7, 18, 0.92)",
            border: "1px solid rgba(255, 255, 255, 0.12)",
            backdropFilter: "blur(12px)",
          }}
        >
          {hasSender && (
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-full bg-purple-500 shadow-[0_0_10px_rgba(168,85,247,0.9)] flex items-center justify-center text-[8px] font-bold text-white">S</div>
              <span className="font-mono text-[9px] text-purple-300 font-bold">CLAIMED SENDER</span>
            </div>
          )}
          {hasServer && (
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.9)] flex items-center justify-center text-[8px] font-bold text-white">M</div>
              <span className="font-mono text-[9px] text-red-300 font-bold">PHYSICAL SERVER</span>
            </div>
          )}
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.9)]" />
            <span className="font-mono text-[9px] text-cyan-300 font-medium">RELAY HOP</span>
          </div>
        </div>
      </div>

      {/* --- BOTTOM-RIGHT: LIVE COORDINATE & RESOLUTION HUD --- */}
      <div className="absolute bottom-4 right-4 z-[1000] pointer-events-none">
        <div
          className="px-3 py-1.5 rounded-lg font-mono text-[9px] text-slate-400 flex items-center gap-2 shadow-lg"
          style={{
            background: "rgba(3, 7, 18, 0.85)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            backdropFilter: "blur(8px)",
          }}
        >
          {cursorPos ? (
            <span>LAT: <strong className="text-cyan-300">{cursorPos.lat.toFixed(4)}°</strong> · LNG: <strong className="text-cyan-300">{cursorPos.lng.toFixed(4)}°</strong></span>
          ) : (
            <span>HOVER TO INSPECT COORDINATES</span>
          )}
        </div>
      </div>

      {/* --- CSS Keyframe Animations for Radar Markers --- */}
      <style>{`
        @keyframes geo-ping-purple {
          0%   { transform: scale(1);   opacity: 0.9; }
          75%  { transform: scale(2.4); opacity: 0;   }
          100% { transform: scale(2.4); opacity: 0;   }
        }
        @keyframes geo-ping-red {
          0%   { transform: scale(1);   opacity: 0.95; }
          75%  { transform: scale(2.4); opacity: 0;    }
          100% { transform: scale(2.4); opacity: 0;    }
        }
        @keyframes geo-spin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
        @keyframes geo-spin-reverse {
          from { transform: rotate(360deg); }
          to   { transform: rotate(0deg); }
        }
        .leaflet-container { background: #030712 !important; outline: none; }
        .ofm-popup .leaflet-popup-content-wrapper {
          background: transparent !important;
          border: none !important;
          box-shadow: none !important;
          padding: 0 !important;
          border-radius: 0 !important;
        }
        .ofm-popup .leaflet-popup-content { margin: 0 !important; }
        .ofm-popup .leaflet-popup-tip-container { display: none !important; }
        .leaflet-control-attribution, .leaflet-control-zoom { display: none !important; }
      `}</style>
    </div>
  );
}
