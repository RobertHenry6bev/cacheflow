#ifndef AHA_ROI_H
#define AHA_ROI_H

#include <stdint.h>

enum {
  AHA_ROI_INSTRUCTION = 0x1<<3,
  AHA_ROI_REALTIME =    0x1 << 2,
  AHA_ROI_PRINTF =      0x1 << 1,
};

extern uint32_t aha_roi_start(uint32_t, uint32_t);
extern uint32_t aha_roi_stop(uint32_t, uint32_t);

#endif  // AHA_ROI_H
