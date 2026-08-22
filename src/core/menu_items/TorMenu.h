#ifndef __TOR_MENU_H__
#define __TOR_MENU_H__

#include <MenuItemInterface.h>

class TorMenu : public MenuItemInterface {
public:
    TorMenu() : MenuItemInterface("Tor") {}

    void optionsMenu(void);
    void drawIcon(float scale);
    bool hasTheme() { return false; }
    const String& themePath() override {
        static String empty = "";
        return empty;
    }
};

#endif
