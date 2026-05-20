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

      dark: 0,

      diffuse: 2,

      mapSamples: 16000,

      mapBrightness: 12,

      baseColor: [0.3, 0.3, 0.3],

      markerColor: [0, 1, 1],

      glowColor: [0, 0.8, 1],

      atmosphereColor: [0, 0.8, 1],

      atmosphereAltitude: 0.2,

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

        {
          location: [55.7558, 37.6173],
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