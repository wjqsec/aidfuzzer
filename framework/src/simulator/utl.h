inline bool find_value_32(uint32_t *data, int len, uint32_t val)
{
    for(int i = 0; i < len; i ++)
    {
        if(data[i] == val)
            return true;
    }
    return false;
}
inline bool find_value_16(uint16_t *data, int len, uint16_t val)
{
    for(int i = 0; i < len; i ++)
    {
        if(data[i] == val)
            return true;
    }
    return false;
}