import Globe from "react-globe.gl"

export default function AttackMap() {
  const attacks = [
    {
      startLat: 55.7558,
      startLng: 37.6173,
      endLat: 20.5937,
      endLng: 78.9629,
      color: ["#00FFFF", "#FF00FF"],
    },
    {
      startLat: 40.7128,
      startLng: -74.006,
      endLat: 28.6139,
      endLng: 77.209,
      color: ["#FF0000", "#00FFFF"],
    },
  ]

  return (
    <div className="mt-10 bg-white/[0.03] border border-white/10 rounded-3xl overflow-hidden backdrop-blur-3xl shadow-2xl hover:-translate-y-1 hover:shadow-cyan-500/10 transition-all duration-300">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 p-6 md:p-8 border-b border-white/10">
        <div>
          <h2 className="text-2xl md:text-3xl font-black">
            Global Threat Map
          </h2>

          <p className="text-gray-400 mt-2 text-sm md:text-base">
            Live cyber attack visualization
          </p>
        </div>

        <div className="px-4 py-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-sm w-fit">
          LIVE TRACKING
        </div>
      </div>

      {/* Globe */}
      <div className="h-[350px] md:h-[450px] xl:h-[550px] w-full flex items-center justify-center">
        <Globe
          width={1200}
          height={550}
          backgroundColor="rgba(0,0,0,0)"
          globeImageUrl="https://unpkg.com/three-globe/example/img/earth-night.jpg"
          bumpImageUrl="https://unpkg.com/three-globe/example/img/earth-topology.png"
          arcsData={attacks}
          arcColor={"color"}
          arcDashLength={0.4}
          arcDashGap={4}
          arcDashAnimateTime={2000}
          arcStroke={1.5}
          atmosphereColor="#00FFFF"
          atmosphereAltitude={0.15}
        />
      </div>
    </div>
  )
}