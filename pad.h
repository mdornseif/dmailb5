/* $Id$
 *  --drt@ailis.de
 * 
 * $Log$
 */

#include "stralloc.h"

/* adjust sa to len by cutting it off at the end or by 
   repeating the string until we are at len
*/
unsigned int stralloc_pad(stralloc *sa, int len);
unsigned int stralloc_align(stralloc *sa, int a);
