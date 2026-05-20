import Particles from "react-tsparticles";

const CyberBackground = () => {

  return (

    <Particles
      options={{

        fullScreen: {
          enable: false,
        },

        background: {
          color: "transparent",
        },

        fpsLimit: 60,

        particles: {

          color: {
            value: "#22D3EE",
          },

          links: {
            color: "#22D3EE",
            distance: 150,
            enable: true,
            opacity: 0.15,
            width: 1,
          },

          move: {
            enable: true,
            speed: 1,
          },

          number: {
            value: 45,
          },

          opacity: {
            value: 0.2,
          },

          size: {
            value: 2,
          },

        },
      }}

      className="absolute inset-0 z-0"
    />

  );

};

export default CyberBackground;