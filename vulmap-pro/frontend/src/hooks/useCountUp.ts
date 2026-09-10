import { useEffect, useState, useRef } from 'react'
import { useInView } from 'framer-motion'

interface UseCountUpOptions {
  duration?: number // in ms, default 1500
  decimals?: number
  startOnce?: boolean
}

export function useCountUp(
  endValue: number,
  options: UseCountUpOptions = {}
) {
  const { duration = 1500, decimals = 0, startOnce = true } = options
  const [count, setCount] = useState<number>(0)
  const ref = useRef<HTMLSpanElement | null>(null)
  const isInView = useInView(ref, { once: startOnce, margin: '-50px' })

  useEffect(() => {
    if (!isInView) return

    let startTime: number | null = null
    let animationFrameId: number

    const updateCount = (timestamp: number) => {
      if (!startTime) startTime = timestamp
      const progress = Math.min((timestamp - startTime) / duration, 1)

      // Ease out expo formula
      const easeProgress = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress)
      const current = easeProgress * endValue

      setCount(Number(current.toFixed(decimals)))

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(updateCount)
      } else {
        setCount(endValue)
      }
    }

    animationFrameId = requestAnimationFrame(updateCount)

    return () => {
      if (animationFrameId) cancelAnimationFrame(animationFrameId)
    }
  }, [isInView, endValue, duration, decimals])

  return { count, ref }
}
