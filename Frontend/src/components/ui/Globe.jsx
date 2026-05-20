import createGlobe from "cobe";
import { useEffect, useRef } from "react";

export default function Globe() {

  const canvasRef = useRef(null);

  useEffect(() => {

    let phi = 0;

    const globe = createGlobe(canvasRef.current, {

      devicePixelRatio: 2,

      width: 1200,

      height: 1200,

      phi: 0,

      theta: 0.25,

      dark: 1,

      diffuse: 1.4,

      mapSamples: 30000,

      mapBrightness: 1.8,

      baseColor: [0.1, 0.1, 0.1],

      markerColor: [0.0, 1.0, 1.0],

      glowColor: [0.0, 0.8, 1.0],

      opacity: 1,

      offset: [0, 0],

      scale: 1,

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

        {
          location: [48.8566, 2.3522],
          size: 0.08,
        },

      ],

      onRender: (state) => {

        state.phi = phi;

        phi += 0.004;

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
          maxWidth: "1000px",
          aspectRatio: "1/1",
        }}
      />

    </div>

  );

}