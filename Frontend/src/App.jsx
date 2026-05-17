import {
  Routes,
  Route,
  Navigate,
} from "react-router-dom";

import MainLayout from "./layouts/MainLayout";

import Login from "./pages/login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import ThreatFeed from "./pages/ThreatFeed";
import Analytics from "./pages/Analytics";
import Monitor from "./pages/Monitor";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";

const App = () => {

  const isAuthenticated =
    localStorage.getItem("token");

  return (
    <Routes>

      {/* Public Routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      {/* Protected Layout */}
      <Route
        element={
          isAuthenticated ? (
            <MainLayout />
          ) : (
            <Navigate to="/login" />
          )
        }
      >

        <Route
          path="/dashboard"
          element={<Dashboard />}
        />

        <Route
          path="/threat-feed"
          element={<ThreatFeed />}
        />

        <Route
          path="/analytics"
          element={<Analytics />}
        />

        <Route
          path="/monitor"
          element={<Monitor />}
        />

        <Route
          path="/reports"
          element={<Reports />}
        />

        <Route
          path="/settings"
          element={<Settings />}
        />

      </Route>

      {/* Default Redirect */}
      <Route
        path="*"
        element={
          <Navigate
            to={
              isAuthenticated
                ? "/dashboard"
                : "/login"
            }
          />
        }
      />

    </Routes>
  );
};

export default App;