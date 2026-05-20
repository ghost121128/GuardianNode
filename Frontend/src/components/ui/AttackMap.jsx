import {
  Globe,
} from "lucide-react";

const attacks = [

  "USA → India",
  "Russia → Germany",
  "China → USA",
  "Brazil → UK",

];

const AttackMap = () => {

  return (

    <div className="bg-gray-100 dark:bg-[#0B1120]/80 backdrop-blur-xl border border-gray-200 dark:border-[#1E293B] rounded-[32px] p-7 shadow-2xl transition-all duration-500">

      {/* Header */}
      <div className="flex items-center justify-between mb-6">

        <div>

          <h2 className="text-3xl font-black mb-2">
            Global Attack Map
          </h2>

          <p className="text-gray-500 dark:text-gray-400">
            Real-time cyber attack monitoring
          </p>

        </div>

        <div className="flex items-center gap-2">

          <div className="w-3 h-3 bg-red-400 rounded-full animate-pulse" />

          <span className="text-red-400 text-sm font-bold">
            LIVE
          </span>

        </div>

      </div>

      {/* Globe Area */}
      <div className="relative h-[420px] rounded-3xl overflow-hidden bg-gradient-to-br from-[#07111F] to-[#0B1120] border border-cyan-500/10 flex items-center justify-center">

        {/* Animated Glow */}
        <div className="absolute w-[300px] h-[300px] rounded-full bg-cyan-500/10 blur-3xl animate-pulse" />

        {/* Globe */}
        <div className="relative z-10 text-center">

          <Globe
            size={160}
            className="text-cyan-400 mx-auto animate-spin"
            style={{
              animationDuration: "20s",
            }}
          />

          <p className="text-cyan-400 mt-6 text-xl font-bold">
            LIVE GLOBAL MONITORING
          </p>

        </div>

        {/* Attack Feed */}
        <div className="absolute bottom-6 left-6 right-6 space-y-3">

          {attacks.map((attack, index) => (

            <div
              key={index}

              className="bg-black/30 border border-red-500/10 rounded-2xl px-4 py-3 flex items-center justify-between backdrop-blur-xl"
            >

              <span className="text-gray-300">
                {attack}
              </span>

              <div className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />

            </div>

          ))}

        </div>

      </div>

    </div>

  );

};

export default AttackMap;