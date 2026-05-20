import createGlobe from "cobe";
import {
  useEffect,
  useRef,
} from "react";

export default function Globe() {

  const canvasRef = useRef();

  useEffect(() => {

    let phi = 0;

    const canvas =
      canvasRef.current;

    if (!canvas) return;

    const globe = createGlobe(canvas, {

      devicePixelRatio: 2,

      width: 1200,

      height: 1200,

      phi: 0,

      theta: 0.3,

      dark: 1,

      diffuse: 1.3,

      mapSamples: 20000,

      mapBrightness: 1.2,

      baseColor: [0.02, 0.08, 0.15],

      markerColor: [0.1, 0.8, 1],

      glowColor: [0, 1, 1],

      atmosphereColor: [0, 0.8, 1],

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

        phi += 0.002;

      },

    });

    return () => {

      globe.destroy();

    };

  }, []);

  return (

    <div className="w-full h-full flex items-center justify-center overflow-hidden">

      <canvas

        ref={canvasRef}

        style={{

          width: "100%",

          height: "100%",

          maxWidth: "850px",

          aspectRatio: "1 / 1",

        }}

      />

    </div>

  );

}