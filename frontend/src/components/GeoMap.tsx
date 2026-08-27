import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

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

const PRIMARY_TILE_URL   = "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}";
const FALLBACK_TILE_URL  = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";
const TILE_ATTRIB        = '&copy; <a href="https://www.esri.com/">Esri</a> &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>';

function makeCustomMarker(pt: GeoPoint): L.DivIcon {
  const type = pt.pointType || (pt.isOrigin ? "server" : "hop");
  
  let color = "#06b6d4";
  let size = 14;
  let pulseRing = "";

  if (type === "sender") {
    color = "#a855f7"; // Purple for verified sender identity
    size = 20;
    pulseRing = `
      <div style="
        position:absolute; inset:-8px; border-radius:50%;
        border:2px solid rgba(168,85,247,0.6);
        animation:geo-ping-purple 2.2s ease-out infinite;
      "></div>
    `;
  } else if (type === "server" || pt.isOrigin) {
    color = pt.isSynthetic ? "#f59e0b" : "#ef4444"; // Red for physical server origin
    size = 20;
    pulseRing = `
      <div style="
        position:absolute; inset:-8px; border-radius:50%;
        border:2px solid ${color}88;
        animation:geo-ping-red 1.9s ease-out infinite;
      "></div>
    `;
  }

  return L.divIcon({
    className: "",
    iconSize:   [size + 18, size + 18],
    iconAnchor: [Math.round((size + 18) / 2), Math.round((size + 18) / 2)],
    popupAnchor:[0, -Math.round((size + 18) / 2)],
    html: `
      <div style="
        position:relative;
        width:${size + 18}px;
        height:${size + 18}px;
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
          border:2.5px solid rgba(255,255,255,0.9);
          box-shadow:0 0 14px ${color}, 0 0 28px ${color}66;
          display:flex;
          align-items:center;
          justify-content:center;
          flex-shrink:0;
        ">
          ${type === "sender" ? '<span style="font-size:9px;color:#fff;font-weight:900;font-family:sans-serif;">S</span>' : ''}
          ${type === "server" ? '<span style="font-size:9px;color:#fff;font-weight:900;font-family:sans-serif;">M</span>' : ''}
        </div>
      </div>
    `,
  });
}

function makePopupHtml(pt: GeoPoint, idx: number): string {
  const type = pt.pointType || (pt.isOrigin ? "server" : "hop");
  
  let headerColor = "#06b6d4";
  let title = `▸ RELAY HOP #${idx}`;

  if (type === "sender") {
    headerColor = "#a855f7";
    title = "👤 SENDER IDENTITY ORIGIN";
  } else if (type === "server" || pt.isOrigin) {
    headerColor = pt.isSynthetic ? "#f59e0b" : "#ef4444";
    title = pt.isSynthetic ? "⚠ TRANSMISSION GATEWAY" : "🖥️ PHYSICAL TRANSMISSION SERVER";
  }

  return `
    <div style="
      font-family:'JetBrains Mono',monospace;
      background:#06101a;
      border:1px solid ${headerColor}66;
      border-radius:10px;
      padding:12px 15px;
      min-width:220px;
      box-shadow:0 8px 32px rgba(0,0,0,0.85);
    ">
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:6px;">
        <span style="color:${headerColor};font-size:9px;font-weight:800;letter-spacing:0.12em;">
          ${title}
        </span>
      </div>
      <p style="color:#fff;font-size:13px;font-weight:800;margin:0 0 4px 0;">
        ${pt.city || "Unknown"}, ${pt.country || "Unknown"}
      </p>
      ${pt.org ? `<p style="color:#cbd5e1;font-size:10px;margin:0 0 2px 0;"><b>Org:</b> ${pt.org}</p>` : ""}
      ${pt.ip && pt.ip !== "Unknown" ? `<p style="color:${headerColor};font-size:10px;margin:0 0 2px 0;"><b>IP:</b> ${pt.ip}</p>` : ""}
      ${pt.isp && pt.isp !== "Unknown" ? `<p style="color:#64748b;font-size:9px;margin:0 0 2px 0;"><b>ISP/ASN:</b> ${pt.isp}</p>` : ""}
      ${pt.verificationSource ? `<p style="color:#10b981;font-size:8px;margin:3px 0 0;letter-spacing:0.06em;">✓ ${pt.verificationSource}</p>` : ""}
    </div>
  `;
}

export function GeoMap({ points = [], height = 420 }: GeoMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef       = useRef<L.Map | null>(null);
  const layersRef    = useRef<L.Layer[]>([]);
  const ready = true;

  useEffect(() => {
    if (!containerRef.current) return;

    if (mapRef.current) {
      mapRef.current.remove();
      mapRef.current = null;
      layersRef.current = [];
    }

    // Filter valid points with non-zero coordinates
    const validPoints = points.filter(p => p && (p.lat !== 0 || p.lng !== 0) && !isNaN(p.lat) && !isNaN(p.lng));
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

      // Add Primary Tile Layer (Esri Dark Canvas, No API key needed)
      const tileLayer = L.tileLayer(PRIMARY_TILE_URL, {
        maxZoom:     16,
        attribution: TILE_ATTRIB,
      });

      tileLayer.on("tileerror", () => {
        const fallback = L.tileLayer(FALLBACK_TILE_URL, { 
          maxZoom: 18,
          className: "osm-dark-fallback" 
        });
        fallback.addTo(map);
        layersRef.current.push(fallback);
      });

      tileLayer.addTo(map);
      layersRef.current.push(tileLayer);

      // Route lines if multiple points
      if (validPoints.length > 1) {
        const latlngs = validPoints.map(p => [p.lat, p.lng] as L.LatLngTuple);

        // Glow polyline
        const glow = L.polyline(latlngs, {
          color:   "#a855f7",
          weight:  6,
          opacity: 0.35,
          lineCap: "round",
        }).addTo(map);
        layersRef.current.push(glow);

        // Dashed transmission route
        const line = L.polyline(latlngs, {
          color:     "#06b6d4",
          weight:    2.5,
          opacity:   0.9,
          dashArray: "6 5",
          lineCap:   "round",
        }).addTo(map);
        layersRef.current.push(line);
      }

      // Add Markers
      validPoints.forEach((pt, i) => {
        const icon   = makeCustomMarker(pt);
        const marker = L.marker([pt.lat, pt.lng], { icon });
        const popup  = L.popup({
          className:      "ofm-popup",
          closeButton:    false,
          offset:         [0, -4],
          maxWidth:       280,
          autoPanPadding: [25, 25],
        }).setContent(makePopupHtml(pt, i + 1));

        marker.bindPopup(popup);
        marker.addTo(map);
        layersRef.current.push(marker);
      });

      // Fit bounds
      if (validPoints.length === 1) {
        map.setView([validPoints[0].lat, validPoints[0].lng], 5);
      } else if (validPoints.length > 1) {
        const bounds = L.latLngBounds(validPoints.map(p => [p.lat, p.lng] as L.LatLngTuple));
        map.fitBounds(bounds, { padding: [50, 50], maxZoom: 7 });
      }

      // Invalidate size on load and resize
      map.invalidateSize();
      const timers = [
        setTimeout(() => { if (mapRef.current) mapRef.current.invalidateSize(); }, 60),
        setTimeout(() => { if (mapRef.current) mapRef.current.invalidateSize(); }, 250),
        setTimeout(() => { if (mapRef.current) mapRef.current.invalidateSize(); }, 600),
      ];

      // Auto-resize observer
      let resizeObs: ResizeObserver | null = null;
      if (typeof ResizeObserver !== "undefined" && containerRef.current) {
        resizeObs = new ResizeObserver(() => {
          if (mapRef.current) mapRef.current.invalidateSize();
        });
        resizeObs.observe(containerRef.current);
      }

      return () => {
        timers.forEach(clearTimeout);
        if (resizeObs) resizeObs.disconnect();
        if (mapRef.current) {
          mapRef.current.remove();
          mapRef.current = null;
          layersRef.current = [];
        }
      };

    } catch (e) {
      console.error("Map initialization error:", e);
    }
  }, [JSON.stringify(points)]);

  const hasSender = points.some(p => p.pointType === "sender");
  const hasServer = points.some(p => p.pointType === "server" || p.isOrigin);

  return (
    <div
      className="relative rounded-xl overflow-hidden shadow-2xl"
      style={{
        height,
        background: "#060d17",
        border: "1px solid rgba(0,240,255,0.2)",
      }}
    >
      {/* Loading Spinner */}
      {!ready && (
        <div
          className="absolute inset-0 z-20 flex flex-col items-center justify-center gap-3"
          style={{ background: "#060d17" }}
        >
          <div className="relative w-10 h-10">
            <div className="absolute inset-0 rounded-full border-2 border-slate-800" />
            <div className="absolute inset-0 rounded-full border-2 border-t-cyan-400 animate-spin" />
          </div>
          <p className="font-code text-[10px] text-slate-400 tracking-widest">
            INITIALIZING SATELLITE TELEMETRY MAP…
          </p>
        </div>
      )}

      {/* Map Container */}
      <div ref={containerRef} style={{ width: "100%", height: "100%" }} />

      {/* HUD Overlays */}
      {ready && (
        <>
          {/* Top-Left Telemetry Badge */}
          <div className="absolute top-3 left-3 z-[1000] pointer-events-none">
            <div
              className="px-3 py-1.5 rounded-lg font-mono text-[9px] font-bold tracking-widest text-cyan-300 flex items-center gap-2"
              style={{
                background: "rgba(6,12,24,0.9)",
                border: "1px solid rgba(0,240,255,0.35)",
                backdropFilter: "blur(8px)",
              }}
            >
              <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span>LIVE GEOSPATIAL RADAR · DUAL-NODE</span>
            </div>
          </div>

          {/* Top-Right Legend */}
          <div className="absolute top-3 right-3 z-[1000] pointer-events-none">
            <div
              className="flex items-center gap-3 px-3 py-1.5 rounded-lg"
              style={{
                background: "rgba(6,12,24,0.9)",
                border: "1px solid rgba(255,255,255,0.1)",
                backdropFilter: "blur(8px)",
              }}
            >
              {hasSender && (
                <div className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-purple-400 shadow-[0_0_8px_rgba(168,85,247,0.9)]" />
                  <span className="font-mono text-[9px] text-purple-300 font-bold">SENDER</span>
                </div>
              )}
              {hasServer && (
                <div className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-400 shadow-[0_0_8px_rgba(239,68,68,0.9)]" />
                  <span className="font-mono text-[9px] text-red-300 font-bold">SERVER</span>
                </div>
              )}
              <div className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(6,182,212,0.9)]" />
                <span className="font-mono text-[9px] text-cyan-300">RELAY HOP</span>
              </div>
            </div>
          </div>

          {/* Zoom controls helper */}
          <div className="absolute bottom-3 right-3 z-[1000] pointer-events-none">
            <span className="font-mono text-[8px] text-slate-500 bg-black/60 px-2 py-1 rounded border border-white/[0.05]">
              SCROLL / DRAG TO PAN
            </span>
          </div>
        </>
      )}

      <style>{`
        @keyframes geo-ping-purple {
          0%   { transform: scale(1);   opacity: 0.85; }
          75%  { transform: scale(2.3); opacity: 0;   }
          100% { transform: scale(2.3); opacity: 0;   }
        }
        @keyframes geo-ping-red {
          0%   { transform: scale(1);   opacity: 0.9; }
          75%  { transform: scale(2.3); opacity: 0;   }
          100% { transform: scale(2.3); opacity: 0;   }
        }
        .leaflet-container { background: #060d17 !important; outline: none; }
        .osm-dark-fallback {
          filter: brightness(0.65) invert(1) contrast(3) hue-rotate(200deg) saturate(0.3) brightness(0.7) !important;
        }
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
