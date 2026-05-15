import Particles from "react-tsparticles"

export default function ParticlesBackground() {
  return (
    <Particles
      className="absolute inset-0 z-0"
      options={{
        background: {
          color: {
            value: "transparent",
          },
        },

        fpsLimit: 60,

        particles: {
          color: {
            value: "#00FFFF",
          },

          links: {
            color: "#00FFFF",
            distance: 150,
            enable: true,
            opacity: 0.1,
            width: 1,
          },

          move: {
            enable: true,
            speed: 1,
          },

          number: {
            value: 60,
          },

          opacity: {
            value: 0.15,
          },

          size: {
            value: {
              min: 1,
              max: 3,
            },
          },
        },
      }}
    />
  )
}