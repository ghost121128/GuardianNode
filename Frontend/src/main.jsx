import React from "react";

import ReactDOM from "react-dom/client";

import {
  BrowserRouter,
} from "react-router-dom";

import App from "./App";

import "./index.css";

import {
  ThemeProvider,
} from "./context/ThemeContext";

import {
  Toaster,
} from "react-hot-toast";

ReactDOM.createRoot(
  document.getElementById("root")
).render(

  

    <ThemeProvider>

      <BrowserRouter>

        <App />

        <Toaster
          position="top-right"
        />

      </BrowserRouter>

    </ThemeProvider>

 

);