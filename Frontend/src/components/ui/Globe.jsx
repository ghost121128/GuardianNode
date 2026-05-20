import React, { useEffect, useState } from "react";
import Globe from "react-globe.gl";

export default function CyberGlobe() {

  const [dimensions, setDimensions] = useState({
    width: 800,
    height: 800,
  });

  useEffect(() => {

    const updateSize = () => {

      setDimensions({

        width: window.innerWidth < 768
          ? window.innerWidth - 40
          : 900,

        height: window.innerWidth < 768
          ? 400
          : 700,

      });

    };

    updateSize();

    window.addEventListener(
      "resize",
      updateSize
    );

    return () =>
      window.removeEventListener(
        "resize",
        updateSize
      );

  }, []);

  return (

    <div className="w-full flex items-center justify-center">

      <Globe

        width={dimensions.width}

        height={dimensions.height}

        globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"

        bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"

        backgroundColor="rgba(0,0,0,0)"

        atmosphereColor="#00ffff"

        atmosphereAltitude={0.15}

        arcsData={[

          {

            startLat: 28.6139,
            startLng: 77.2090,

            endLat: 40.7128,
            endLng: -74.0060,

            color: ["#00ffff", "#00ffff"],

          },

          {

            startLat: 51.5072,
            startLng: -0.1276,

            endLat: 35.6762,
            endLng: 139.6503,

            color: ["#00ffff", "#00ffff"],

          },

        ]}

        arcColor={"color"}

        arcStroke={0.5}

        arcDashLength={0.4}

        arcDashGap={0.2}

        arcDashAnimateTime={2000}

      />

    </div>

  );

}