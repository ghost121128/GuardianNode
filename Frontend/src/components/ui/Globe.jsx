import createGlobe from "cobe";
import { useEffect, useRef } from "react";

export default function Globe() {

  const canvasRef = useRef();

  useEffect(() => {

    let phi = 0;

    const globe = createGlobe(canvasRef.current, {

      devicePixelRatio: 2,

      width: 1200,

      height: 1200,

      phi: 0,

      theta: 0.3,

      dark: 1,

      diffuse: 1.2,

      mapSamples: 16000,

      mapBrightness: 6,

      baseColor: [0.05, 0.1, 0.2],

      markerColor: [0, 1, 1],

      glowColor: [0, 1, 1],

      markers: [

        { location: [28.6139, 77.2090], size: 0.1 },

        { location: [40.7128, -74.0060], size: 0.1 },

        { location: [51.5072, -0.1276], size: 0.1 },

        { location: [35.6762, 139.6503], size: 0.1 },

      ],

      onRender: (state) => {

        state.phi = phi;

        phi += 0.003;

      },

    });

    return () => globe.destroy();

  }, []);

  return (

    <canvas
      ref={canvasRef}
      style={{
        width: "100%",
        height: "700px",
      }}
    />

  );

}