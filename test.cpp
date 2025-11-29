#include "lep/low_entropy_protocol.h"

int main()
{
	bool __lep_v0_encoder_test = dixelu::lep::details::v0::compiletime_encoder_test();
	return __lep_v0_encoder_test;
}
