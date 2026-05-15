import { Routes, Route, Navigate } from "react-router-dom";

import Login from "./pages/login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";

const App = () => {

  const isAuthenticated = localStorage.getItem("token");

  return (
    <Routes>

      {/* Public Routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      {/* Protected Dashboard */}
      <Route
        path="/dashboard"
        element={
          isAuthenticated ? (
            <Dashboard />
          ) : (
            <Navigate to="/login" />
          )
        }
      />

      {/* Default Redirect */}
      <Route
        path="*"
        element={
          <Navigate
            to={isAuthenticated ? "/dashboard" : "/login"}
          />
        }
      />

    </Routes>
  );
};

export default App;