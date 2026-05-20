import createGlobe from "cobe";
import { useEffect, useRef } from "react";

export default function Globe() {

  const canvasRef = useRef(null);

  useEffect(() => {

    let phi = 0;

    const globe = createGlobe(canvasRef.current, {

      devicePixelRatio: 2,

      width: 1000,

      height: 1000,

      phi: 0,

      theta: 0.3,

      dark: 1,

      diffuse: 1.8,

      mapSamples: 60000,

      mapBrightness: 1.2,

      baseColor: [0.3, 0.3, 0.3],

      markerColor: [0, 1, 1],

      glowColor: [0, 0.8, 1],

      atmosphereColor: [0, 0.8, 1],

      ambientLight: [1, 1, 1],

      atmosphereAltitude: 0.15,

      markers: [

        {
          location: [28.6139, 77.2090],
          size: 0.08,
        },

        {
          location: [40.7128, -74.0060],
          size: 0.08,
        },

        {
          location: [51.5072, -0.1276],
          size: 0.08,
        },

        {
          location: [35.6762, 139.6503],
          size: 0.08,
        },

      ],

      onRender: (state) => {

        state.phi = phi;

        phi += 0.003;

      },

    });

    return () => globe.destroy();

  }, []);

  return (

    <div className="w-full h-full flex items-center justify-center overflow-hidden">

      <canvas
        ref={canvasRef}
        className="w-full h-full"
        style={{
          maxWidth: "900px",
          aspectRatio: "1 / 1",
        }}
      />

    </div>

  );

}