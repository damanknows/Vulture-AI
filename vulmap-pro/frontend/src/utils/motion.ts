import { type Variants } from 'framer-motion'

export const EXPO_EASE = [0.16, 1, 0.3, 1] as const

export const fadeUp = (delay = 0): Variants => ({
  hidden: { opacity: 0, y: 20 },
  show: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.6,
      ease: [0.16, 1, 0.3, 1],
      delay,
    },
  },
})

export const staggerContainer = (stagger = 0.1): Variants => ({
  hidden: {},
  show: {
    transition: {
      staggerChildren: stagger,
    },
  },
})

export const magneticButton = {
  whileHover: { scale: 1.02, boxShadow: '0 0 30px -5px rgba(0, 245, 212, 0.3)' },
  whileTap: { scale: 0.98 },
  transition: { type: 'spring', stiffness: 400, damping: 17 },
}
