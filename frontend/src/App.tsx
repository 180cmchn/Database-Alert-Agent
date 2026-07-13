import { Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { AlertsPage } from "./pages/AlertsPage";
import { CreateAlertPage } from "./pages/CreateAlertPage";
import { DashboardPage } from "./pages/DashboardPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { RunbooksPage } from "./pages/RunbooksPage";
import { SettingsPage } from "./pages/SettingsPage";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<DashboardPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="alerts/new" element={<CreateAlertPage />} />
        <Route path="alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="runbooks" element={<RunbooksPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
