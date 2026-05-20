import createGlobe from "cobe";
import { useEffect, useRef } from "react";

export default function Globe() {

  const canvasRef = useRef(null);
  const globeRef = useRef(null);

  useEffect(() => {

    if (globeRef.current) return;

    let phi = 0;

    const canvas = canvasRef.current;

    const size = 900;

    globeRef.current = createGlobe(canvas, {

      devicePixelRatio: 2,

      width: size * 2,

      height: size * 2,

      phi: 0,

      theta: 0.3,

      dark: 0.9,

      diffuse: 2,

      mapSamples: 16000,

      mapBrightness: 8,

      baseColor: [0.2, 0.2, 0.2],

      markerColor: [0, 1, 1],

      glowColor: [0, 1, 1],

      atmosphereColor: [0, 1, 1],

      atmosphereAltitude: 0.2,

      markers: [

        {
          location: [28.6139, 77.2090],
          size: 0.05,
        },

        {
          location: [40.7128, -74.0060],
          size: 0.05,
        },

        {
          location: [51.5072, -0.1276],
          size: 0.05,
        },

        {
          location: [35.6762, 139.6503],
          size: 0.05,
        },

      ],

      onRender: (state) => {

        state.phi = phi;

        phi += 0.004;

      },

    });

    return () => {

      if (globeRef.current) {

        globeRef.current.destroy();
        globeRef.current = null;

      }

    };

  }, []);

  return (

    <div className="w-full h-full flex items-center justify-center">

      <canvas
        ref={canvasRef}
        style={{
          width: "100%",
          height: "100%",
          maxWidth: "850px",
          aspectRatio: "1",
        }}
      />

    </div>

  );

}