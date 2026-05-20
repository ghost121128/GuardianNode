import createGlobe from "cobe";
import { useEffect, useRef } from "react";

export default function Globe() {

  const canvasRef = useRef();

  useEffect(() => {

    let phi = 0;

    const canvas = canvasRef.current;

    const globe = createGlobe(canvas, {

      devicePixelRatio: 2,

      width: 1000,

      height: 1000,

      phi: 0,

      theta: 0.25,

      dark: 1,

      diffuse: 1.5,

      mapSamples: 20000,

      mapBrightness: 1.2,

      baseColor: [0.15, 0.15, 0.15],

      glowColor: [0, 0.8, 1],

      atmosphereColor: [0, 0.8, 1],

      atmosphereAltitude: 0.15,

      markerColor: [0, 1, 1],

      markers: [

        { location: [28.6139, 77.2090], size: 0.05 },

        { location: [40.7128, -74.006], size: 0.05 },

        { location: [51.5072, -0.1276], size: 0.05 },

        { location: [35.6762, 139.6503], size: 0.05 },

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
        className="w-[700px] h-[700px] max-w-full max-h-full"
      />

    </div>

  );

}