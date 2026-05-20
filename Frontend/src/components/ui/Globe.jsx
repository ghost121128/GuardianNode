import createGlobe from "cobe";
import { useEffect, useRef } from "react";

export default function Globe() {

  const canvasRef = useRef(null);

  useEffect(() => {

    let phi = 0;

    const globe = createGlobe(canvasRef.current, {

      devicePixelRatio: 2,

      width: 800,

      height: 800,

      phi: 0,

      theta: 0.3,

      dark: 1,

      diffuse: 1.4,

      mapSamples: 40000,

      mapBrightness: 1.2,

      baseColor: [0.1, 0.1, 0.1],

      markerColor: [0.1, 0.8, 1],

      glowColor: [0, 0.8, 1],

      atmosphereColor: [0, 0.8, 1],

      atmosphereAltitude: 0.18,

      markers: [

        { location: [28.6139, 77.2090], size: 0.06 },

        { location: [40.7128, -74.0060], size: 0.06 },

        { location: [51.5072, -0.1276], size: 0.06 },

        { location: [35.6762, 139.6503], size: 0.06 },

      ],

      onRender: (state) => {

        state.phi = phi;

        phi += 0.002;

      },

    });

    return () => globe.destroy();

  }, []);

  return (

    <div className="w-full flex items-center justify-center">

      <canvas
        ref={canvasRef}
        style={{
          width: "100%",
          maxWidth: "700px",
          aspectRatio: "1/1",
        }}
      />

    </div>

  );

}