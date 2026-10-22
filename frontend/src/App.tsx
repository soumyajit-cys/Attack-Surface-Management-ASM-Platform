import Router from './router'
import { ToastProvider } from './components/ui/Toaster'
import StepUpDialog from './components/StepUpDialog'

export default function App() {
  return (
    <ToastProvider>
      <Router />
      <StepUpDialog />
    </ToastProvider>
  )
}
