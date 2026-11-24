#include <stddef.h>

#define SELF_MOD_COLOUR_CHANNELS   3
#define SELF_MOD_MAX_SCREEN_WIDTH  1024
#define SELF_MOD_MAX_SCREEN_HEIGHT 768

#pragma data_seg(".data")
static void (*ConvertRoutine)() = NULL;
static int Unused = 0;
static int LongEdgeColour[SELF_MOD_COLOUR_CHANNELS] = {0};
static int ShortEdgeColour[SELF_MOD_COLOUR_CHANNELS] = {0};
static int SpanColour[SELF_MOD_COLOUR_CHANNELS] = {0};
static int RowOffset[SELF_MOD_MAX_SCREEN_HEIGHT] = {0};
static int Horizon[SELF_MOD_MAX_SCREEN_WIDTH] = {0};
#pragma data_seg()
